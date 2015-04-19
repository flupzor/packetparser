#
# Copyright (c) 2015 Alexander Schrijver <alex@flupzor.nl>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

class PacketContainer(object):
    def __init__(self, data, upper_layer=None, lower_layer=None):
        self.data = data
        self.upper_layer = upper_layer
        self.lower_layer = lower_layer

    def __getattr__(self, name, *args, **kwargs):
        if 'data' in self.__dict__ and name in self.__dict__['data']:
            return self.__dict__['data'][name]

        raise AttributeError()

    def __setattr__(self, name, value, *args, **kwargs):
        if 'data' in self.__dict__ and name in self.__dict__['data']:
            self.__dict__['data'][name] = value

        super(PacketContainer, self).__setattr__(name, value, *args, **kwargs)

#   def __delattr__
#   XXX: implement

    @classmethod
    def parse(cls, buf, extra=None):
        raise NotImplementedError()
