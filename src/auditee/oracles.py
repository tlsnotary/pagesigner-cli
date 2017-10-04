import re
from xml.dom import minidom
import urllib2
from base64 import b64decode,b64encode


snapshotID = 'snap-2c1fab9b'
imageID = 'ami-15192302'

oracle_modulus = [160, 219, 242, 71, 45, 207, 8, 59, 79, 223, 247, 65, 118, 79, 92, 119, 51, 107, 26, 66, 49, 174, 16, 126, 182, 43, 221, 31, 56, 45, 138, 214, 69, 246, 225, 36, 162, 66, 241, 197, 137, 45, 96, 224, 13, 213, 205, 59, 163, 225, 202, 179, 175, 99, 112, 135, 37, 149, 17, 87, 168, 15, 93, 245, 138, 106, 137, 39, 236, 125, 88, 170, 131, 191, 243, 226, 163, 209, 235, 135, 152, 55, 101, 152, 168, 71, 152, 48, 157, 184, 96, 196, 19, 187, 171, 238, 168, 208, 59, 101, 32, 119, 124, 132, 16, 43, 162, 173, 242, 160, 81, 39, 173, 128, 196, 136, 86, 121, 80, 10, 12, 233, 53, 185, 147, 114, 124, 68, 216, 23, 186, 156, 117, 53, 21, 52, 200, 223, 222, 52, 201, 180, 208, 17, 165, 33, 212, 48, 55, 111, 235, 30, 189, 200, 248, 218, 90, 191, 253, 172, 93, 146, 140, 248, 150, 70, 93, 221, 161, 172, 179, 156, 58, 230, 161, 111, 95, 45, 90, 27, 102, 206, 136, 222, 127, 191, 203, 43, 156, 198, 50, 21, 232, 229, 41, 110, 195, 37, 206, 62, 126, 249, 50, 1, 45, 157, 87, 13, 172, 255, 161, 110, 34, 151, 53, 233, 96, 201, 139, 149, 220, 67, 182, 190, 23, 135, 40, 93, 221, 214, 41, 159, 219, 183, 119, 132, 86, 205, 216, 161, 97, 0, 28, 124, 91, 1, 125, 209, 106, 47, 220, 75, 108, 224, 143, 139, 150, 188, 23, 23, 15, 203, 42, 231, 76, 253, 239, 195, 6, 111, 246, 30, 31, 156, 115, 190, 52, 52, 37, 213, 102, 0, 150, 110, 7, 150, 120, 61, 190, 135, 244, 228, 107, 87, 87, 223, 24, 212, 178, 205, 198, 61, 140, 16, 44, 6, 224, 168, 214, 53, 201, 247, 121, 138, 240, 72, 7, 73, 149, 181, 133, 147, 124, 221, 222, 46, 121, 176, 200, 162, 48, 33, 59, 241, 254, 30, 247, 7, 165, 91, 166, 113, 133, 119, 234, 229, 129, 162, 64, 164, 205, 172, 79, 182, 147, 63, 226, 133, 82, 201, 26, 251, 17, 227, 251, 0, 25, 238, 38, 70, 85, 229, 92, 103, 180, 87, 60, 159, 148, 113, 135, 33, 169, 101, 184, 138, 239, 71, 40, 187, 1, 133, 134, 49, 160, 236, 165, 160, 250, 77, 140, 213, 234, 172, 225, 231, 174, 21, 29, 220, 60, 221, 177, 21, 26, 245, 163, 155, 187, 28, 66, 50, 159, 184, 97, 107, 14, 86, 26, 145, 171, 88, 137, 238, 212, 36, 79, 123, 183, 190, 202, 177, 201, 132, 121, 178, 127, 149, 13, 184, 243, 47, 132, 120, 153, 28, 41, 169, 72, 251, 152, 86, 153, 212, 63, 247, 29, 52, 173, 26, 252, 249, 63, 146, 188, 53, 97, 244, 90, 123, 71, 47, 195, 142, 91, 123, 213, 151, 166, 229, 208, 154, 127, 208, 243, 253, 168, 154, 171, 110, 253, 153, 129, 176, 27, 155, 195, 103, 49, 211, 182, 55]

oracle = {'name':'tlsnotarygroup4',
                "IP":"54.152.4.116",
                "port":"10011",
                'DI':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstances&Expires=2020-01-01&InstanceId=i-4b3aff5c&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=U4mRuXbeUVo%2B6phevN8bqo6rIEcAqBYqyRGcnnMEZHs%3D',
                'DV':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeVolumes&Expires=2020-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-006fce93&Signature=BdIMf03m9e%2BGVmtWZvqXesd%2FYR0w9HrduJd%2BgbH1iHo%3D',
                'GCO':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetConsoleOutput&Expires=2020-01-01&InstanceId=i-4b3aff5c&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=NMHOUMWy33jO%2FxehPRfwLBdVAv0k1sjQxoNzX4Gmco4%3D',
                'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetUser&Expires=2020-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=24VJthLGnh74s%2FPIUAkfC93ysanNSffO9fCep%2FeMc74%3D',
                'DIA':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2020-01-01&InstanceId=i-4b3aff5c&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=EogpSx9tPLzejFx1dl%2FC1nRk%2FtP%2BXL44CkfwOL20pno%3D',
                'instanceId': 'i-4b3aff5c',
                "modulus":[160, 219, 242, 71, 45, 207, 8, 59, 79, 223, 247, 65, 118, 79, 92, 119, 51, 107, 26, 66, 49, 174, 16, 126, 182, 43, 221, 31, 56, 45, 138, 214, 69, 246, 225, 36, 162, 66, 241, 197, 137, 45, 96, 224, 13, 213, 205, 59, 163, 225, 202, 179, 175, 99, 112, 135, 37, 149, 17, 87, 168, 15, 93, 245, 138, 106, 137, 39, 236, 125, 88, 170, 131, 191, 243, 226, 163, 209, 235, 135, 152, 55, 101, 152, 168, 71, 152, 48, 157, 184, 96, 196, 19, 187, 171, 238, 168, 208, 59, 101, 32, 119, 124, 132, 16, 43, 162, 173, 242, 160, 81, 39, 173, 128, 196, 136, 86, 121, 80, 10, 12, 233, 53, 185, 147, 114, 124, 68, 216, 23, 186, 156, 117, 53, 21, 52, 200, 223, 222, 52, 201, 180, 208, 17, 165, 33, 212, 48, 55, 111, 235, 30, 189, 200, 248, 218, 90, 191, 253, 172, 93, 146, 140, 248, 150, 70, 93, 221, 161, 172, 179, 156, 58, 230, 161, 111, 95, 45, 90, 27, 102, 206, 136, 222, 127, 191, 203, 43, 156, 198, 50, 21, 232, 229, 41, 110, 195, 37, 206, 62, 126, 249, 50, 1, 45, 157, 87, 13, 172, 255, 161, 110, 34, 151, 53, 233, 96, 201, 139, 149, 220, 67, 182, 190, 23, 135, 40, 93, 221, 214, 41, 159, 219, 183, 119, 132, 86, 205, 216, 161, 97, 0, 28, 124, 91, 1, 125, 209, 106, 47, 220, 75, 108, 224, 143, 139, 150, 188, 23, 23, 15, 203, 42, 231, 76, 253, 239, 195, 6, 111, 246, 30, 31, 156, 115, 190, 52, 52, 37, 213, 102, 0, 150, 110, 7, 150, 120, 61, 190, 135, 244, 228, 107, 87, 87, 223, 24, 212, 178, 205, 198, 61, 140, 16, 44, 6, 224, 168, 214, 53, 201, 247, 121, 138, 240, 72, 7, 73, 149, 181, 133, 147, 124, 221, 222, 46, 121, 176, 200, 162, 48, 33, 59, 241, 254, 30, 247, 7, 165, 91, 166, 113, 133, 119, 234, 229, 129, 162, 64, 164, 205, 172, 79, 182, 147, 63, 226, 133, 82, 201, 26, 251, 17, 227, 251, 0, 25, 238, 38, 70, 85, 229, 92, 103, 180, 87, 60, 159, 148, 113, 135, 33, 169, 101, 184, 138, 239, 71, 40, 187, 1, 133, 134, 49, 160, 236, 165, 160, 250, 77, 140, 213, 234, 172, 225, 231, 174, 21, 29, 220, 60, 221, 177, 21, 26, 245, 163, 155, 187, 28, 66, 50, 159, 184, 97, 107, 14, 86, 26, 145, 171, 88, 137, 238, 212, 36, 79, 123, 183, 190, 202, 177, 201, 132, 121, 178, 127, 149, 13, 184, 243, 47, 132, 120, 153, 28, 41, 169, 72, 251, 152, 86, 153, 212, 63, 247, 29, 52, 173, 26, 252, 249, 63, 146, 188, 53, 97, 244, 90, 123, 71, 47, 195, 142, 91, 123, 213, 151, 166, 229, 208, 154, 127, 208, 243, 253, 168, 154, 171, 110, 253, 153, 129, 176, 27, 155, 195, 103, 49, 211, 182, 55]
}


def get_xhr(url):
    xml = urllib2.urlopen(url).read()
    return minidom.parseString(xml)

def getChildNodes(x):
    return [a for a in x[0].childNodes if not a.nodeName=='#text']

#assuming both events happened on the same day, get the time
#difference between them in seconds
#the time string looks like "2015-04-15T19:00:59.000Z"
def getSecondsDelta (later, sooner):
    assert (len(later) == 24)
    if (later[:11] != sooner[:11]):
      return 999999; #not on the same day
    laterTime = later[11:19].split(':')
    soonerTime = sooner[11:19].split(':')
    laterSecs = int(laterTime[0])*3600+int(laterTime[1])*60+int(laterTime[2])
    soonerSecs = int(soonerTime[0])*3600+int(soonerTime[1])*60+int(soonerTime[2])
    return laterSecs - soonerSecs


def modulus_from_pubkey(pem_pubkey):
    b64_str = ''
    lines = pem_pubkey.split('\n')
    #omit header and footer lines
    for i in range(1,len(lines)-1):
        b64_str += lines[i]
    der = b64decode(b64_str)
    #last 5 bytes are 2 DER bytes and 3 bytes exponent, our pubkey is the preceding 512 bytes
    pubkey = der[len(der)-517:len(der)-5]
    return pubkey

def checkDescribeInstances(xmlDoc, instanceId, IP):
  try:
    rs = xmlDoc.getElementsByTagName('reservationSet')
    assert rs.length == 1
    rs_items = getChildNodes(rs)
    assert len(rs_items) == 1
    ownerId = rs_items[0].getElementsByTagName('ownerId')[0].firstChild.data
    isets = rs_items[0].getElementsByTagName('instancesSet')
    assert isets.length == 1
    instances = getChildNodes(isets)
    assert len(instances) == 1
    parent = instances[0]
    assert parent.getElementsByTagName('instanceId')[0].firstChild.data == instanceId
    assert parent.getElementsByTagName('imageId')[0].firstChild.data == imageID
    assert parent.getElementsByTagName('instanceState')[0].getElementsByTagName('name')[0].firstChild.data == 'running'
    launchTime = parent.getElementsByTagName('launchTime')[0].firstChild.data
    assert parent.getElementsByTagName('ipAddress')[0].firstChild.data == IP
    assert parent.getElementsByTagName('rootDeviceType')[0].firstChild.data == 'ebs'
    assert parent.getElementsByTagName('rootDeviceName')[0].firstChild.data == '/dev/xvda'
    devices = parent.getElementsByTagName('blockDeviceMapping')[0].getElementsByTagName('item')
    assert devices.length == 1
    assert devices[0].getElementsByTagName('deviceName')[0].firstChild.data == '/dev/xvda'
    assert devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('status')[0].firstChild.data == 'attached'
    volAttachTime = devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('attachTime')[0].firstChild.data
    volumeId = devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('volumeId')[0].firstChild.data
    #get seconds from "2015-04-15T19:00:59.000Z"
    assert getSecondsDelta(volAttachTime, launchTime) <= 3
    assert parent.getElementsByTagName('virtualizationType')[0].firstChild.data == 'hvm'
    return {'ownerId':ownerId, 'volumeId':volumeId, 'volAttachTime':volAttachTime, 'launchTime':launchTime}
  except:
    return False


def checkDescribeVolumes(xmlDoc, instanceId, volumeId, volAttachTime):
  try:
    v = xmlDoc.getElementsByTagName('volumeSet')
    volumes = getChildNodes(v)
    assert len(volumes) == 1
    volume = volumes[0]
    assert volume.getElementsByTagName('volumeId')[0].firstChild.data == volumeId
    assert volume.getElementsByTagName('snapshotId')[0].firstChild.data == snapshotID
    assert volume.getElementsByTagName('status')[0].firstChild.data == 'in-use'
    volCreateTime = volume.getElementsByTagName('createTime')[0].firstChild.data
    attVolumes = volume.getElementsByTagName('attachmentSet')[0].getElementsByTagName('item')
    assert attVolumes.length == 1
    attVolume = attVolumes[0];
    assert attVolume.getElementsByTagName('volumeId')[0].firstChild.data == volumeId
    assert attVolume.getElementsByTagName('instanceId')[0].firstChild.data == instanceId
    assert attVolume.getElementsByTagName('device')[0].firstChild.data == '/dev/xvda'
    assert attVolume.getElementsByTagName('status')[0].firstChild.data == 'attached'
    attTime = attVolume.getElementsByTagName('attachTime')[0].firstChild.data
    assert volAttachTime == attTime
    #Crucial: volume was created from snapshot and attached at the same instant
    #this guarantees that there was no time window to modify it
    assert getSecondsDelta(attTime, volCreateTime) == 0
    return True
  except:
    return False



def checkGetConsoleOutput(xmlDoc, instanceId, launchTime):
  try:
    assert xmlDoc.getElementsByTagName('instanceId')[0].firstChild.data == instanceId
    timestamp = xmlDoc.getElementsByTagName('timestamp')[0].firstChild.data
    #prevent funny business: last consoleLog entry no later than 5 minutes after instance starts
    assert getSecondsDelta(timestamp, launchTime) <= 300
    b64data = xmlDoc.getElementsByTagName('output')[0].firstChild.data
    logstr = b64decode(b64data)
    sigmark = 'PageSigner public key for verification'
    pkstartmark = '-----BEGIN PUBLIC KEY-----'
    pkendmark = '-----END PUBLIC KEY-----'

    mark_start = logstr.index(sigmark)
    assert mark_start != -1
    pubkey_start = mark_start + logstr[mark_start:].index(pkstartmark)
    pubkey_end = pubkey_start+ logstr[pubkey_start:].index(pkendmark) + len(pkendmark)
    pk = logstr[pubkey_start:pubkey_end]
    assert len(pk) > 0
    return pk
  except:
    return False




# "userData" allows to pass an arbitrary script to the instance at launch. It MUST be empty.
# This is a sanity check because the instance is stripped of the code which parses userData.
def checkDescribeInstanceAttribute(xmlDoc, instanceId):
  try:
    assert xmlDoc.getElementsByTagName('instanceId')[0].firstChild.data == instanceId
    assert not xmlDoc.getElementsByTagName('userData')[0].firstChild
    return True
  except:
    return False

def checkGetUser(xmlDoc, ownerId):
    #try:
    assert xmlDoc.getElementsByTagName('UserId')[0].firstChild.data == ownerId
    assert xmlDoc.getElementsByTagName('Arn')[0].firstChild.data[-(len(ownerId) + len(':root')):] == ownerId+':root'
    #except:
    #return False
    return True

def check_oracle(o):
    print ('Verifying PageSigner AWS oracle server, this may take up to a minute...')
    xmlDoc = get_xhr(o['DI'])
    CDIresult = checkDescribeInstances(xmlDoc, o['instanceId'], o['IP'])
    if not CDIresult:
      raise Exception('checkDescribeInstances')
    print ('check 1 of 5 successful')
    
    xmlDoc = get_xhr(o['DV'])
    CDVresult = checkDescribeVolumes(xmlDoc, o['instanceId'], CDIresult['volumeId'], CDIresult['volAttachTime'])
    if not CDVresult:
      raise Exception('checkDescribeVolumes')
    print ('check 2 of 5 successful')
    
    xmlDoc = get_xhr(o['GU'])
    CGUresult = checkGetUser(xmlDoc, CDIresult['ownerId'])
    if not CGUresult:
      raise Exception('checkGetUser')
    print ('check 3 of 5 successful')
    
    xmlDoc = get_xhr(o['GCO'])
    GCOresult = checkGetConsoleOutput(xmlDoc, o['instanceId'], CDIresult['launchTime'])
    if not GCOresult:
      raise Exception('checkGetConsoleOutput')
    print ('check 4 of 5 successful')
    
    sigmod_binary = bytearray('').join(map(chr,o['modulus']))
    if modulus_from_pubkey(GCOresult) != sigmod_binary:
      raise Exception("modulus from pubkey")

    xmlDoc = get_xhr(o['DIA'])
    DIAresult = checkDescribeInstanceAttribute(xmlDoc, o['instanceId'])
    if not DIAresult:
      raise Exception('checkDescribeInstanceAttribute')
    print ('check 5 of 5 successful')
     
    mark = 'AWSAccessKeyId=';
    ids = [];
    #"AWSAccessKeyId" should be the same to prove that the queries are made on behalf of AWS user "root".
    #The attacker can be a user with limited privileges for whom the API would report only partial information.
    for url in [o['DI'], o['DV'], o['GU'], o['GCO'], o['DIA']]:
      start = url.index(mark)+len(mark);
      ids.append(url[start:start + url[start:].index('&')])
    assert len(set(ids)) == 1
    print('oracle verification successfully finished')
