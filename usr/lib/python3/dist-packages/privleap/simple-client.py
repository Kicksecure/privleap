#!/usr/bin/python3 -u

import privleap

sesh = privleap.PrivleapSession("", is_control_session = True)
item = privleap.PrivleapControlClientCreateMessage("aaron")
sesh.send_message(item)
