/**
 * Copyright 2015 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

#include <Python.h>
#include <structmember.h>

#include <fcntl.h>
#include <sys/fanotify.h>

#ifndef Py_TYPE
#define Py_TYPE(ob) (((PyObject*)(ob))->ob_type)
#endif /* Py_TYPE */

#ifndef PyVarObject_HEAD_INIT
#define PyVarObject_HEAD_INIT(type, size) PyObject_HEAD_INIT(type) size,
#endif /* PyVarObject_HEAD_INIT */

#if PY_MAJOR_VERSION >= 3
static char *byte_arg_str = "y#";
static char *byte_arg_str_tuple = "(y#)";
static char *byte_arg_str_event_tuple = "y#O";
#else
static char *byte_arg_str = "s#";
static char *byte_arg_str_tuple = "(s#)";
static char *byte_arg_str_event_tuple = "s#O";
#endif /* PY_MAJOR_VERSION >= 3 */

PyDoc_STRVAR(
    fanotify_doc,
    "Functions and classes for interacting with the Linux fanotify interface.\n"
    "\n"
    "This is a very thin interface to the fanotify C library. Most of these\n"
    "functions and classes have equivalent forms in linux/fanotify.h. See man\n"
    "7 fanotify, man 2 fanotify_init, and man 2 fanotify_mark for full\n"
    "documentation.\n");

static PyObject *module = NULL;
static PyObject *FanotifyError = NULL;

typedef struct {
  PyObject_HEAD;
  struct fanotify_event_metadata metadata;
  PyObject *data;
} fanotify_EventMetadata;

PyDoc_STRVAR(
    EventMetadata_init_doc,
    "EventMetadata constructor to represent struct fanotify_event_metadata.\n"
    "\n"
    "See the manpages for fanotify and linux/fanotify.h for details on what\n"
    "these fields mean. The object created contains a field for each entry in\n"
    "the struct and a 'data' field that contains any extra data included for\n"
    "the event. Currently this is unused in the kernel but may contain data\n"
    "in the future.\n"
    "\n"
    "Args:\n"
    "  buf: A buffer containing fanotify event metadata.\n");
static int EventMetadata_init(fanotify_EventMetadata *self, PyObject *args,
                                PyObject *kwargs) {
  static char *kwlist[] = {"buf", NULL};
  const void *buf = NULL;
  Py_ssize_t buf_size = 0;

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, byte_arg_str, kwlist, &buf,
                                   &buf_size)) {
    return -1;
  }
  const struct fanotify_event_metadata *event = buf;
  memcpy(&self->metadata, event, sizeof(self->metadata));

  size_t data_size = buf_size - sizeof(*event);
  buf += sizeof(*event);

  PyObject *temp_data = self->data;
  self->data = Py_BuildValue(byte_arg_str, buf, data_size);
  Py_XDECREF(temp_data);

  return 0;
}

static void EventMetadata_dealloc(fanotify_EventMetadata *self) {
  Py_XDECREF(self->data);
  PyObject_Free((PyObject*)Py_TYPE(self));
}

static PyMemberDef EventMetadata_members[] = {
  {"event_len", T_UINT, offsetof(fanotify_EventMetadata, metadata.event_len), 0,
                                 "Fanotify event len"},
  {"vers", T_UBYTE, offsetof(fanotify_EventMetadata, metadata.vers), 0,
    "Fanotify version"},
  {"reserved", T_UBYTE, offsetof(fanotify_EventMetadata, metadata.reserved), 0,
    "Fanotify reserved value"},
  {"metadata_len", T_USHORT,
    offsetof(fanotify_EventMetadata, metadata.metadata_len), 0,
    "Fanotify metadata len"},
  {"mask", T_ULONGLONG, offsetof(fanotify_EventMetadata, metadata.mask), 0,
    "Fanotify mask"},
  {"fd", T_INT, offsetof(fanotify_EventMetadata, metadata.fd), 0,
    "Fanotify fd"},
  {"pid", T_INT, offsetof(fanotify_EventMetadata, metadata.pid), 0,
    "Fanotify pid"},
  {"data", T_OBJECT_EX, offsetof(fanotify_EventMetadata, data), 0,
    "Fanotify extra data"},
  {NULL}
};

static PyTypeObject fanotify_EventMetadataType = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "fanotify.EventMetadata",           /* tp_name */
  sizeof(fanotify_EventMetadata),     /* tp_basicsize */
  0,                                  /* tp_itemsize */
  (destructor)EventMetadata_dealloc,  /* tp_dealloc */
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  0,                                  /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,                 /* tp_flags */
  EventMetadata_init_doc,             /* tp_doc */
  0,                                  /* tp_traverse */
  0,                                  /* tp_clear */
  0,                                  /* tp_richcompare */
  0,                                  /* tp_weaklistoffset */
  0,                                  /* tp_iter */
  0,                                  /* tp_iternext */
  0,                                  /* tp_methods */
  EventMetadata_members,              /* tp_members */
  0,                                  /* tp_getset */
  0,                                  /* tp_base */
  0,                                  /* tp_dict */
  0,                                  /* tp_descr_get */
  0,                                  /* tp_descr_set */
  0,                                  /* tp_dictoffset */
  (initproc)EventMetadata_init,       /* tp_init */
  0,                                  /* tp_alloc */
  0,                                  /* tp_new */
};

PyDoc_STRVAR(
    fanotify_Init_doc,
    "Init(flags, event_f_flags) -> fd\n"
    "\n"
    "Wrapper for fanotify_init\n"
    "\n"
    "Creates an fanotify fd and returns it to the caller.\n"
    "\n"
    "Args:\n"
    "  flags: Zero or more FAN_* flags. One and only one of FAN_CLASS_* must\n"
    "    be\n"
    "  specified in addition to other flags.\n"
    "  event_f_flags: File status flags for the fanoty file descriptor. For\n"
    "  example O_RDONLY, O_WRONLY, etc.\n"
    "\n"
    "Raises:\n"
    "  OSError: Raised when fanotify_init sets errno.\n"
    "\n"
    "Returns:\n"
    "  A file descriptor for the fanotify watcher.\n");
PyObject *fanotify_Init(PyObject *self, PyObject *args, PyObject *kwargs) {
  static char *kwlist[] = {"flags", "event_f_flags", NULL};
  unsigned int flags = 0;
  unsigned int event_f_flags = 0;

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "II", kwlist, &flags,
                                   &event_f_flags)) {
    return NULL;
  }

  int fd = fanotify_init(flags, event_f_flags);
  if (fd == -1) {
    return PyErr_SetFromErrno(PyExc_OSError);
  }

  return PyLong_FromLong(fd);
}

PyDoc_STRVAR(
    fanotify_Mark_doc,
    "Mark(fanotify_fd, flags, mask, dirfd, pathname)\n"
    "\n"
    "Wrapper for fanotify_mark\n"
    "\n"
    "Marks a mount, path, or directory on the given fanotify fd. Note that\n"
    "the interactions with dirfd and pathname are somewhat complex. Please\n"
    "refer to the manpage for fanotify_mark for information on exactly how\n"
    "these are handled.\n"
    "\n"
    "Args:\n"
    "  fanotify_fd: The fanotify file desciptor returned from Init.\n"
    "  flags: Zero or more FAN_MARK_* flags. One and only one of\n"
    "    FAN_MARK_ADD, FAN_MARK_REMOVE, or FAN_MARK_FLUSH must be specified.\n"
    "  mask: Flags defining the type of events that should be listened for.\n"
    "  dirfd: The filesystem object to be marked if pathname is None in most\n"
    "  cases. Please see the manpage for fanotify_mark for more details.\n"
    "  pathname: Path to mark in most cases. Please see the manpage for\n"
    "    fanotify_mark for more details. For any cases where the manpage\n"
    "    mentions passing NULL for the pathname pass None.\n"
    "\n"
    "Raises:\n"
    "  OSError: Raised when fanotify_mark sets errno.\n");
PyObject *fanotify_Mark(PyObject *self, PyObject *args, PyObject *kwargs) {
  static char *kwlist[] = {"fanotify_fd", "flags", "mask", "dirfd", "pathname",
    NULL};
  int fanotify_fd = -1;
  unsigned int flags = 0;
  uint64_t mask = 0;
  int dirfd = -1;
  const char *pathname = NULL;

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iIKiz", kwlist, &fanotify_fd,
                                   &flags, &mask, &dirfd, &pathname)) {
    return NULL;
  }

  int rv = fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname);
  if (rv == -1) {
    /* The user is allowed to pass in None for the pathname if they desire. */
    if (pathname) {
      return PyErr_SetFromErrnoWithFilename(PyExc_OSError, pathname);
    } else {
      return PyErr_SetFromErrno(PyExc_OSError);
    }
  }

  Py_RETURN_NONE;
}

PyDoc_STRVAR(
    fanotify_EventNext_doc,
    "EventNext(buf) -> (buf, event)\n"
    "\n"
    "Wrapper for FAN_EVENT_NEXT macro.\n"
    "\n"
    "Takes a buffer and returns a tuple containing any remaining data in the\n"
    "buffer after the next event in the stream and an EventMetadata object\n"
    "representing the next event.\n"
    "\n"
    "IMPORTANT: The fd field in the event returned by this function MUST be\n"
    "closed with os.close by the caller unless you particularly like leaking\n"
    "file descriptors.\n"
    "\n"
    "The data passed to this function should generally come from a call to\n"
    "os.read from the fanotify file descriptor returned by Init.\n"
    "\n"
    "Args:\n"
    "  buf: fanotify event stream (as a string) containing one or more\n"
    "    events.\n"
    "\n"
    "Raises:\n"
    "  FanotifyError: If there is no event in the stream to extract.\n"
    "\n"
    "Returns:\n"
    "  (buf, event): string containing the rest of the data in the stream and\n"
    "    the event that was extracted from the stream.\n");
PyObject *fanotify_EventNext(PyObject *self, PyObject *args, PyObject *kwargs) {
  static char *kwlist[] = {"buf", NULL};
  const void *buf = NULL;
  Py_ssize_t buf_size = 0;


  if (!PyArg_ParseTupleAndKeywords(args, kwargs, byte_arg_str, kwlist, &buf,
                                   &buf_size)) {
    return NULL;
  }

  const struct fanotify_event_metadata *event = buf;
  if (!FAN_EVENT_OK(event, buf_size)) {
    PyErr_SetString(
        FanotifyError,
        "Attempted to get NextEvent from event stream that is not OK");
    return NULL;
  }

  Py_ssize_t new_buf_size = buf_size;
  const struct fanotify_event_metadata *next_event =
      FAN_EVENT_NEXT(event, new_buf_size);
  const char *new_buf = (const void *)next_event;

  PyObject *event_metadata_args = Py_BuildValue(byte_arg_str_tuple, buf,
                                                buf_size - new_buf_size);
  if (event_metadata_args == NULL) {
    return NULL;
  }
  PyObject *event_metadata = PyObject_CallObject(
      (PyObject *)&fanotify_EventMetadataType, event_metadata_args);
  Py_DECREF(event_metadata_args);

  return Py_BuildValue(byte_arg_str_event_tuple, new_buf, new_buf_size, event_metadata);
}

PyDoc_STRVAR(
    fanotify_EventOk_doc,
    "EventOk(buf) -> bool\n"
    "\n"
    "Wrapper for FAN_EVENT_OK macro.\n"
    "\n"
    "Checks if there is an fanotify event in the provided stream and returns\n"
    "True if there is.\n"
    "\n"
    "Args:\n"
    "  buf: The stream to check if there is an fanotify event in.\n"
    "\n"
    "Returns:\n"
    "  True if there is a good event, False otherwise.\n");
PyObject *fanotify_EventOk(PyObject *self, PyObject *args, PyObject *kwargs) {
  static char *kwlist[] = {"buf", NULL};
  const void *buf = NULL;
  Py_ssize_t buf_size = 0;

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, byte_arg_str, kwlist, &buf,
                                   &buf_size)) {
    return NULL;
  }

  const struct fanotify_event_metadata *event = buf;
  if (FAN_EVENT_OK(event, buf_size)) {
    Py_RETURN_TRUE;
  }

  Py_RETURN_FALSE;
}

PyDoc_STRVAR(
    fanotify_Response_doc,
    "Response(fd, response) -> buf\n"
    "\n"
    "Wrapper for creating a struct fanotify_response.\n"
    "\n"
    "Populate a struct fanotify_response and return the raw bytes\n"
    "representing the struct. The data returend by this function should\n"
    "generally be written to the fanotify file descriptor returned by Init\n"
    "with os.write.\n"
    "\n"
    "Args:\n"
    "  fd: The fd field of the EventMetadata object to create a response for.\n"
    "  response: The response decision. This will often be FAN_ALLOW or\n"
    "    FAN_DENY.\n"
    "\n"
    "Returns:\n"
    "  A string containing the raw bytes of the fanotify_response struct,\n"
    "  specifically a str object for Python 2 and bytes object for\n"
    "  Python 3.\n");
PyObject *fanotify_Response(PyObject *self, PyObject *args, PyObject *kwargs) {
  static char *kwlist[] = {"fd", "response", NULL};
  int fd = -1;
  uint32_t response = 0;

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iI", kwlist, &fd,
                                   &response)) {
    return NULL;
  }

  struct fanotify_response fanotify_response = {fd, response};

  return Py_BuildValue(byte_arg_str, &fanotify_response, sizeof(fanotify_response));
}

static PyMethodDef fanotify_methods[] = {
  {"Init", (PyCFunction)fanotify_Init, METH_VARARGS | METH_KEYWORDS,
    fanotify_Init_doc},
  {"Mark", (PyCFunction)fanotify_Mark, METH_VARARGS | METH_KEYWORDS,
    fanotify_Mark_doc},
  {"EventNext", (PyCFunction)fanotify_EventNext, METH_VARARGS | METH_KEYWORDS,
    fanotify_EventNext_doc},
  {"EventOk", (PyCFunction)fanotify_EventOk, METH_VARARGS | METH_KEYWORDS,
    fanotify_EventOk_doc},
  {"Response", (PyCFunction)fanotify_Response, METH_VARARGS | METH_KEYWORDS,
    fanotify_Response_doc},
};

/* Module definition struct for python3. */
#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
  PyModuleDef_HEAD_INIT,
  "fanotify",       /* m_name */
  fanotify_doc,     /* m_doc */
  0,                /* m_size */
  fanotify_methods, /* m_methods */
  NULL,             /* m_reload */
  NULL,             /* m_traverse */
  NULL,             /* m_clear */
  NULL              /* m_free */
};
#endif /* PY_MAJOR_VERSION >= 3 */

PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit_fanotify(void) {
  module = PyModule_Create(&moduledef);
  if (module == NULL) {
    return NULL;
  }
#else
initfanotify(void) {
  module = Py_InitModule3("fanotify", fanotify_methods, fanotify_doc);
  if (module == NULL) {
    return;
  }
#endif /* PY_MAJOR_VERSION >= 3 */
  FanotifyError = PyErr_NewException("fanotify.FanotifyError", NULL, NULL);
  Py_INCREF(FanotifyError);
  PyModule_AddObject(module, "FanotifyError", FanotifyError);

  fanotify_EventMetadataType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&fanotify_EventMetadataType) < 0) {
#if PY_MAJOR_VERSION >= 3
    return NULL;
#else
    return;
#endif /* PY_MAJOR_VERSION >= 3 */
  }
  Py_INCREF(&fanotify_EventMetadataType);
  PyModule_AddObject(module, "EventMetadata",
                     (PyObject *)&fanotify_EventMetadataType);

  PyModule_AddIntMacro(module, FAN_ACCESS);
  PyModule_AddIntMacro(module, FAN_MODIFY);
  PyModule_AddIntMacro(module, FAN_CLOSE_WRITE);
  PyModule_AddIntMacro(module, FAN_CLOSE_NOWRITE);
  PyModule_AddIntMacro(module, FAN_OPEN);
  PyModule_AddIntMacro(module, FAN_Q_OVERFLOW);
  PyModule_AddIntMacro(module, FAN_OPEN_PERM);
  PyModule_AddIntMacro(module, FAN_ACCESS_PERM);
  PyModule_AddIntMacro(module, FAN_ONDIR);
  PyModule_AddIntMacro(module, FAN_EVENT_ON_CHILD);
  PyModule_AddIntMacro(module, FAN_CLOSE);
  PyModule_AddIntMacro(module, FAN_CLOEXEC);
  PyModule_AddIntMacro(module, FAN_NONBLOCK);
  PyModule_AddIntMacro(module, FAN_CLASS_NOTIF);
  PyModule_AddIntMacro(module, FAN_CLASS_CONTENT);
  PyModule_AddIntMacro(module, FAN_CLASS_PRE_CONTENT);
  PyModule_AddIntMacro(module, FAN_ALL_CLASS_BITS);
  PyModule_AddIntMacro(module, FAN_UNLIMITED_QUEUE);
  PyModule_AddIntMacro(module, FAN_UNLIMITED_MARKS);
  PyModule_AddIntMacro(module, FAN_ALL_INIT_FLAGS);
  PyModule_AddIntMacro(module, FAN_MARK_ADD);
  PyModule_AddIntMacro(module, FAN_MARK_REMOVE);
  PyModule_AddIntMacro(module, FAN_MARK_DONT_FOLLOW);
  PyModule_AddIntMacro(module, FAN_MARK_ONLYDIR);
  PyModule_AddIntMacro(module, FAN_MARK_MOUNT);
  PyModule_AddIntMacro(module, FAN_MARK_IGNORED_MASK);
  PyModule_AddIntMacro(module, FAN_MARK_IGNORED_SURV_MODIFY);
  PyModule_AddIntMacro(module, FAN_MARK_FLUSH);
  PyModule_AddIntMacro(module, FAN_ALL_MARK_FLAGS);
  PyModule_AddIntMacro(module, FAN_ALL_EVENTS);
  PyModule_AddIntMacro(module, FAN_ALL_PERM_EVENTS);
  PyModule_AddIntMacro(module, FAN_ALL_OUTGOING_EVENTS);
  PyModule_AddIntMacro(module, FANOTIFY_METADATA_VERSION);
  PyModule_AddIntMacro(module, FAN_ALLOW);
  PyModule_AddIntMacro(module, FAN_DENY);
  PyModule_AddIntMacro(module, FAN_NOFD);
  PyModule_AddIntMacro(module, FAN_Q_OVERFLOW);

#if PY_MAJOR_VERSION >= 3
  return module;
#endif /* PY_MAJOR_VERSION >= 3 */
}
