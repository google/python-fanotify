# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

import os
import io
import unittest

import fanotify

# This test event is for a read on fd 4 with pid 7345.
TEST_EVENT = b'\x18\x00\x00\x00\x03\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00' + \
             b'\x04\x00\x00\x00\xb1\x1c\x00\x00'
# This test response is for fd 4 with FAN_ALLOW.
TEST_RESPONSE = b'\x04\x00\x00\x00\x01\x00\x00\x00'


class FanotifyTest(unittest.TestCase):

  def TestInit(self):
    with self.assertRaises(OSError):
      fanotify.Init(fanotify.FAN_CLOEXEC | fanotify.FAN_CLASS_CONTENT,
                    os.O_RDONLY)

  def TestMark(self):
    with self.assertRaises(OSError):
      fanotify.Mark(-1, 0, 0, 0, 'fakepath')

  def TestEventNext(self):
    remaining_buf, event = fanotify.EventNext(TEST_EVENT)
    self.assertEqual(remaining_buf, b'')
    self.assertEqual(event.fd, 4)
    self.assertEqual(event.pid, 7345)

  def TestEventNextRaisesError(self):
    with self.assertRaises(fanotify.FanotifyError):
      fanotify.EventNext(b'')

  def TestEventOk(self):
    self.assertEqual(fanotify.EventOk(TEST_EVENT), True)
    self.assertEqual(fanotify.EventOk(b''), False)

  def TestResponse(self):
    self.assertEqual(fanotify.Response(4, fanotify.FAN_ALLOW), TEST_RESPONSE)

  def TestReadLoop(self):
    # Create a buffer with 1024 events in it
    r = io.BytesIO(TEST_EVENT * 1024)
    w = io.BytesIO()

    # Continue reading and handling events until we've seen all 1024
    c = 0
    while c < 1024:
      # The real fanotify fd won't return partial events, but StringIO will. To
      # combat that we only read in multiples of the event structure size.
      buf = r.read(len(TEST_EVENT) * 16)
      while fanotify.EventOk(buf):
        buf, event = fanotify.EventNext(buf)
        res = fanotify.Response(event.fd, fanotify.FAN_ALLOW)
        w.write(res)
        c += 1

    self.assertEqual(w.getvalue(), TEST_RESPONSE * 1024)
