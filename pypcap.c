#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <errno.h>
#include <python2.6/Python.h>
#include <pcap.h>

static PyObject* version( PyObject* self, PyObject* args )
{
	return Py_BuildValue( "i", 10 );
}

typedef struct{
	PyObject_HEAD
	pcap_t *handle;
} PypcapObject;

static void pcap_dealloc( PyObject* self )
{
	PypcapObject* pcap = ( PypcapObject*) self;
	pcap_close( pcap->handle );
	pcap->ob_type->tp_free( self );
}

static PyTypeObject PypcapType = {
	PyObject_HEAD_INIT( 0 )
	0,
	"pcap",
	sizeof( PypcapObject ),
	0,                         /*tp_itemsize*/
	pcap_dealloc,              /*tp_dealloc*/
	0,                         /*tp_print*/
	0,                         /*tp_getattr*/
	0,                         /*tp_setattr*/
	0,                         /*tp_compare*/
	0,                         /*tp_repr*/
	0,                         /*tp_as_number*/
	0,                         /*tp_as_sequence*/
	0,                         /*tp_as_mapping*/
	0,                         /*tp_hash */
	0,                         /*tp_call*/
	0,                         /*tp_str*/
	0,                         /*tp_getattro*/
	0,                         /*tp_setattro*/
	0,                         /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,        /*tp_flags*/
	"pcap objects",           /* tp_doc */
};

static void setpcaperr( PypcapObject *t ){
	PyErr_SetString( PyExc_Exception, pcap_geterr(t->handle) );
}

static PyObject* lookupdev( PyObject* self, PyObject* args )
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev( errbuf );
	if( dev == NULL ){
		PyErr_SetString( PyExc_Exception, errbuf );
		return 0;
	}
	else{
		return PyString_FromString( dev );
	}
	Py_RETURN_NONE;
}

static PyObject* pypcap_pcap( PyObject* self, PyObject* args )
{
	static char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = NULL;
	if(PyTuple_Size(args)==0){
		PyObject* devo = lookupdev( self, args );
		if( devo == NULL ){
			PyErr_SetString( PyExc_Exception, "lookup dev error");
			return 0; // memeory leak 
		}
		dev = PyString_AsString( devo );
		Py_DECREF( devo );}
	else{
		dev = PyString_AsString( PyTuple_GET_ITEM(args,0) );
	}
	PypcapObject* pcap = (PypcapObject*) PyType_GenericNew( &PypcapType, NULL, NULL );
	pcap->handle = pcap_open_live( dev, BUFSIZ, 1, 500, errbuf );
	if( pcap->handle == NULL ){
		PyErr_SetString( PyExc_Exception, errbuf );
		return 0;
	}
	return (PyObject*)pcap;
}

static PyObject* pcap_getiter( PyObject* self )
{
	return Py_INCREF( self ), self;
}

static PyObject* pcap_iternext( PyObject* self )
{
	struct pcap_pkthdr* header;
	const u_char* packet;
	PypcapObject* pcap = (PypcapObject*)self;
//	printf("!!! handle %p", pcap->handle );
	while(1){
		int res = 0;
		if ( PyErr_CheckSignals() ) return 0;
		Py_BEGIN_ALLOW_THREADS;
		res = pcap_next_ex( pcap->handle, &header, &packet );
		Py_END_ALLOW_THREADS;
		if( res == 0 ) continue ;
		if( res < 0 ){
			PyErr_SetString( PyExc_Exception, pcap_geterr( pcap->handle ) );
			return 0;
		}
		PyTupleObject* r = (PyTupleObject*) PyTuple_New( 2 );
		PyTuple_SET_ITEM( r, 0, PyFloat_FromDouble( (double)(header->ts.tv_usec)/1000 + (double)header->ts.tv_sec ) );
		PyTuple_SET_ITEM( r, 1, PyString_FromStringAndSize( (char*)packet, header->len ) );
		return (PyObject*)r;
	}
}

static PyObject* pypcap_setfilter( PypcapObject* self, PyObject* arg )
{
	const char * filter = PyString_AsString( arg );
	u_int netmask = 0xffffffff;
	struct bpf_program fcode;
	if( pcap_compile( self->handle, &fcode, filter, 0, netmask ) < 0 ){
		PyErr_SetString( PyExc_Exception, pcap_geterr( self->handle ) );
		return 0;
	}
	if( pcap_setfilter( self->handle, &fcode ) < 0 ){
		PyErr_SetString( PyExc_Exception, pcap_geterr( self->handle ) );
		return 0;
	}
	Py_INCREF( Py_None );
	return Py_None;
}

static PyObject* pypcap_send( PypcapObject* self, PyObject* arg)
{
	char *s;
	int len;
	PyString_AsStringAndSize( arg, &s, &len );
	int r = pcap_sendpacket( self->handle, s, len );
	if(r==0) {
		Py_RETURN_NONE;
	}
	else{
		setpcaperr(self);
		return 0;
	}
}

static PyObject* tunopen( PyObject* self, PyObject* name ){
	struct ifreq ifr;
	int fd=0; int err=0;
	char *dev = PyString_AsString( name );
	if(dev==NULL){
		PyErr_BadArgument();
		return NULL;
	}
		if( (fd=open("/dev/net/tun", O_RDWR)) < 0 ){
		PyErr_SetFromErrno(PyExc_Exception);
		return NULL;
	}
	memset( &ifr, 0, sizeof ifr );
	ifr.ifr_flags = IFF_TAP;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if( (err=ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0 ){
		close(fd); PyErr_SetFromErrno(PyExc_Exception);
		return NULL;	
	}
	return PyLong_FromLong( fd );
}

static PyMethodDef PypcapMethods[] = {
	{"version", version, METH_VARARGS, "get version"},
	{"lookupdev", lookupdev, METH_VARARGS, "lookupdev"},
	{"pcap", pypcap_pcap, METH_VARARGS, "get pcap object"},
	{"tunopen", tunopen, METH_O, "" },
	{ NULL, NULL, 0, NULL }
};

static PyMethodDef pcap_methods[] = {
	{ "setfilter", (PyCFunction)pypcap_setfilter, METH_O, "set filter"},
	{ "send", (PyCFunction)pypcap_send, METH_O, "send packet"},
	{ NULL, NULL, 0, NULL }
};

int some(){
	return 19991;
}

PyMODINIT_FUNC initpypcap( void ){
//( void ) Py_InitModule("pypcap", PypcapMethods );
	PyObject* m = Py_InitModule3("pypcap", PypcapMethods, "pypcap module" );
	Py_INCREF( &PypcapType );
	PypcapType.ob_type = &PyType_Type;
	PypcapType.tp_new  = PyType_GenericNew;
	PypcapType.tp_iter = pcap_getiter;
	PypcapType.tp_iternext = pcap_iternext;
	PypcapType.tp_methods = pcap_methods;
	assert( PyType_Ready( &PypcapType ) >= 0);
	PyModule_AddObject( m, "pypcap", (PyObject*)&PypcapType);
}

