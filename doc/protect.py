#!/usr/bin/python
#
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

"""An tool to deny access to a specific file as a documentation example.

Here we specifically deny access to a file if the user accessing the file isn't
root.
"""

from __future__ import print_function
import os
import sys

import fanotify


def IsRootProcess(pid):
  return os.stat('/proc/{}'.format(pid)).st_uid == 0


def main():
  if len(sys.argv) != 2:
    print('Usage: {} <path>'.format(sys.argv[0]))
    sys.exit(1)

  fan_fd = fanotify.Init(fanotify.FAN_CLASS_CONTENT, os.O_RDONLY)
  fanotify.Mark(fan_fd, fanotify.FAN_MARK_ADD, fanotify.FAN_OPEN_PERM, -1,
                sys.argv[1])

  # Loop continuously rejecting events that don't match root's uid.
  while True:
    buf = os.read(fan_fd, 4096)
    assert buf
    while fanotify.EventOk(buf):
      buf, event = fanotify.EventNext(buf)
      if IsRootProcess(event.pid):
        print('Allowing open from root pid {}'.format(event.pid))
        response = fanotify.FAN_ALLOW
      else:
        print('Denying open from pid {}'.format(event.pid))
        response = fanotify.FAN_DENY
      os.write(fan_fd, fanotify.Response(event.fd, response))
      os.close(event.fd)
    assert not buf

if __name__ == '__main__':
  main()
