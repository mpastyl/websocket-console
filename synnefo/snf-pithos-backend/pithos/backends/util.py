# Copyright 2011-2012 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.

from objpool import ObjectPool
from new import instancemethod
from select import select
from traceback import print_exc
from pithos.backends import connect_backend

USAGE_LIMIT = 500


class PithosBackendPool(ObjectPool):
    def __init__(self, size=None, db_module=None, db_connection=None,
                 block_module=None, block_path=None, block_umask=None,
                 queue_module=None, queue_hosts=None,
                 queue_exchange=None, free_versioning=True,
                 astakos_url=None, service_token=None,
                 astakosclient_poolsize=None,
                 block_params=None,
                 public_url_security=None,
                 public_url_alphabet=None,
                 account_quota_policy=None,
                 container_quota_policy=None,
                 container_versioning_policy=None
        ):
        super(PithosBackendPool, self).__init__(size=size)
        self.db_module = db_module
        self.db_connection = db_connection
        self.block_module = block_module
        self.block_path = block_path
        self.block_umask = block_umask
        self.queue_module = queue_module
        self.block_params = block_params
        self.queue_hosts = queue_hosts
        self.queue_exchange = queue_exchange
        self.astakos_url = astakos_url
        self.service_token = service_token
        self.astakosclient_poolsize = astakosclient_poolsize
        self.free_versioning = free_versioning
        self.public_url_security = public_url_security
        self.public_url_alphabet = public_url_alphabet
        self.account_quota_policy = account_quota_policy
        self.container_quota_policy = container_quota_policy
        self.container_versioning_policy = container_versioning_policy

    def _pool_create(self):
        backend = connect_backend(
                db_module=self.db_module,
                db_connection=self.db_connection,
                block_module=self.block_module,
                block_path=self.block_path,
                block_umask=self.block_umask,
                queue_module=self.queue_module,
                block_params=self.block_params,
                queue_hosts=self.queue_hosts,
                queue_exchange=self.queue_exchange,
                astakos_url=self.astakos_url,
                service_token=self.service_token,
                astakosclient_poolsize=self.astakosclient_poolsize,
                free_versioning=self.free_versioning,
                public_url_security=self.public_url_security,
                public_url_alphabet=self.public_url_alphabet,
                account_quota_policy=self.account_quota_policy,
                container_quota_policy=self.container_quota_policy,
                container_versioning_policy=self.container_versioning_policy)

        backend._real_close = backend.close
        backend.close = instancemethod(_pooled_backend_close, backend,
                                       type(backend))
        backend._pool = self
        backend._use_count = USAGE_LIMIT
        backend.messages = []
        return backend

    def _pool_verify(self, backend):
        wrapper = backend.wrapper
        conn = wrapper.conn
        if conn.closed:
            return False

        if conn.in_transaction():
            conn.close()
            return False

        try:
            fd = conn.connection.connection.fileno()
            r, w, x = select([fd], (), (), 0)
            if r:
                conn.close()
                return False
        except:
            print_exc()
            return False

        return True

    def _pool_cleanup(self, backend):
        c = backend._use_count - 1
        if c < 0:
            backend._real_close()
            return True

        backend._use_count = c
        wrapper = backend.wrapper
        if wrapper.trans is not None:
            conn = wrapper.conn
            if conn.closed:
                wrapper.trans = None
            else:
                wrapper.rollback()
        backend.messages = []
        return False


def _pooled_backend_close(backend):
    backend._pool.pool_put(backend)
