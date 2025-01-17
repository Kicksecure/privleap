#!/usr/bin/python3 -u

import privleap
sock = privleap.PrivleapSocket(privleap.PrivleapSocketType.CONTROL)
sesh = sock.get_session()
rslt = sesh.get_message()
print(rslt.user_name)
