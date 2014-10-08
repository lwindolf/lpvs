#!/usr/bin/python


# From http://stackoverflow.com/questions/3206319/how-do-i-compare-rpm-versions-in-python
#
# (c) 2014 Steve Kehlet

import rpm
import sys
from rpmUtils.miscutils import stringToVersion

if len(sys.argv) != 3:
    print "Usage: %s <rpm1> <rpm2>"
    sys.exit(1)

def vercmp((e1, v1, r1), (e2, v2, r2)):
    return rpm.labelCompare((e1, v1, r1), (e2, v2, r2))

(e1, v1, r1) = stringToVersion(sys.argv[1])
(e2, v2, r2) = stringToVersion(sys.argv[2])

rc = vercmp((e1, v1, r1), (e2, v2, r2))
if rc > 0:
    #print "%s:%s-%s is newer" % (e1, v1, r1)
    sys.exit(-1)

elif rc == 0:
    sys.exit(0)

elif rc < 0:
    #print "%s:%s-%s is newer" % (e2, v2, r2)
    sys.exit(1)
