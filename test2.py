import argparse
import sys
import boto3
import terminaltables

ec2 = boto3.client('ec2', 'eu-west-1')
instance_id = ec2.describe_instances()


def getoptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="This will help you out.")
    parser.add_argument("-n", "--name", help="Instance Name.")
    parser.add_argument("-o", "--operating_system", help="Name of the\
    Operating System.")
    parser.add_argument("-p", "--patch_date", help="Patch Date.")
    parser.add_argument("-ip", "--ip_address", help="Instance ip-address.")
    parser.add_argument("-d", "--disk", help="Name of the hard disk.")
    parser.add_argument("-it", "--instance_type", help="Type of the instance.")
    parser.add_argument("-a", "--availability_zone", help="The availability\
    zone of the instance.")
    parser.add_argument("-s", "--security_group", help="The security group of\
    the Instance.")
    options = parser.parse_args(args)
    return options


options = getoptions(sys.argv[1:])

filters = []

for instance_type in vars(options):
    if options.instance_type is not None:
        filters.append({'Name': 'instance-type', 'Values': \
        [options.instance_type]}, )
        break

for instance_name in vars(options):
    if options.name is not None:
        filters.append({'Name': 'tag:Name', 'Values': [options.name]}, )
        break

for os in vars(options):
    if options.operating_system is not None:
        filters.append({'Name': 'tag:Betriebssystem', 'Values': \
        [options.operating_system]}, )
        break

for patchdate in vars(options):
    if options.patch_date is not None:
        filters.append({'Name': 'tag:PatchDate', 'Values': \
        [options.patch_date]}, )
        break

for ip in vars(options):
    if options.ip_address is not None:
        filters.append({'Name': 'private-ip-address', 'Values': \
        [options.ip_address]}, )
        break

for disk in vars(options):
    if options.disk is not None:
        filters.append({'Name': 'tag:DeviceName', 'Values': [options.disk]}, )

for a_zone in vars(options):
    if options.availability_zone is not None:
        filters.append({'Name': 'availability-zone', 'Values': \
        [options.availability_zone]}, )
        break

for s_group in vars(options):
    if options.security_group is not None:
        filters.append({'Name': 'instance.group-name', 'Values': \
        [options.security_group]}, )
        break

data = [
    ["Name", "Betriebssystem", "PatchDate", "Private IP", "Festplatten",
     "Instance Type", "Availability Zone", "Security Group"]
]
table = terminaltables.AsciiTable(data)

output = ec2.describe_instances(Filters=filters)
print(filters)

for reservation in output["Reservations"]:
    for instance in reservation["Instances"]:

        # Name
        input_name = ""
        for tags in instance["Tags"]:
            if tags["Key"] == 'Name':
                input_name = tags["Value"]

        # Betriebssystem
        input_os = ""
        for tags in instance["Tags"]:
            if tags["Key"] == 'Betriebssystem':
                input_os = tags["Value"]

        # PatchDate
        input_pd = ""
        for tags in instance["Tags"]:
            if tags["Key"] == 'PatchDate':
                input_pd = tags["Value"]

        # Groups
        input_sg = ""
        for group in instance["SecurityGroups"]:
            input_sg += group["GroupName"]

            if instance["SecurityGroups"][-1] != group:
                input_sg += " "

        # Festplatten
        input_fp = ""
        for DeviceName in instance["BlockDeviceMappings"]:
            input_fp += DeviceName["DeviceName"]

            if instance["BlockDeviceMappings"][-1] != DeviceName:
                input_fp += " | "

        row = []
        row.append(input_name)
        row.append(input_os)
        row.append(input_pd)
        row.append(instance["PrivateIpAddress"])
        row.append(input_fp)
        row.append(instance["InstanceType"])
        row.append(instance["Placement"]["AvailabilityZone"])
        row.append(input_sg)
        data.append(row)

    print(table.table)

"""
{
  'Reservations': [{
    'Groups': [],
    'Instances': [{
      'AmiLaunchIndex': 0,
      'ImageId': 'ami-02df9ea15c1778c9c',
      'InstanceId': 'i-004c4a48f752f3ec5',
      'InstanceType': 't2.micro',
      'KeyName': 'BFITest',
      'LaunchTime': datetime.datetime(2019, 11, 19, 12, 19, 42, tzinfo =
      tzutc()),
      'Monitoring': {
        'State': 'disabled'
      },
      'Placement': {
        'AvailabilityZone': 'eu-west-1c',
        'GroupName': '',
        'Tenancy': 'default'
      },
      'PrivateDnsName': 'ip-172-31-2-125.eu-west-1.compute.internal',
      'PrivateIpAddress': '172.31.2.125',
      'ProductCodes': [],
      'PublicDnsName': '',
      'State': {
        'Code': 80,
        'Name': 'stopped'
      },
      'StateTransitionReason': 'User initiated (2019-11-19 12:56:26 GMT)',
      'SubnetId': 'subnet-b58115d1',
      'VpcId': 'vpc-a44de5c0',
      'Architecture': 'x86_64',
      'BlockDeviceMappings': [{
        'DeviceName': '/dev/sda1',
        'Ebs': {
          'AttachTime': datetime.datetime(2019, 10, 30, 16, 1, 29, tzinfo =
          tzutc()),
          'DeleteOnTermination': True,
          'Status': 'attached',
          'VolumeId': 'vol-00d5fdd69ad785ebf'
        }
      }],
      'ClientToken': '',
      'EbsOptimized': False,
      'EnaSupport': True,
      'Hypervisor': 'xen',
      'NetworkInterfaces': [{
        'Attachment': {
          'AttachTime': datetime.datetime(2019, 10, 30, 16, 1, 28, tzinfo =
          tzutc()),
          'AttachmentId': 'eni-attach-0338d0c62959337fd',
          'DeleteOnTermination': True,
          'DeviceIndex': 0,
          'Status': 'attached'
        },
        'Description': '',
        'Groups': [{
          'GroupName': 'launch-wizard-9',
          'GroupId': 'sg-0d9c3489a8deecc92'
        }],
        'Ipv6Addresses': [],
        'MacAddress': '02:55:60:e9:69:7e',
        'NetworkInterfaceId': 'eni-0048eb38a1b24dbe7',
        'OwnerId': '032304311013',
        'PrivateDnsName': 'ip-172-31-2-125.eu-west-1.compute.internal',
        'PrivateIpAddress': '172.31.2.125',
        'PrivateIpAddresses': [{
          'Primary': True,
          'PrivateDnsName': 'ip-172-31-2-125.eu-west-1.compute.internal',
          'PrivateIpAddress': '172.31.2.125'
        }],
        'SourceDestCheck': True,
        'Status': 'in-use',
        'SubnetId': 'subnet-b58115d1',
        'VpcId': 'vpc-a44de5c0',
        'InterfaceType': 'interface'
      }],
      'RootDeviceName': '/dev/sda1',
      'RootDeviceType': 'ebs',
      'SecurityGroups': [{
        'GroupName': 'launch-wizard-9',
        'GroupId': 'sg-0d9c3489a8deecc92'
      }],
      'SourceDestCheck': True,
      'StateReason': {
        'Code': 'Client.UserInitiatedShutdown',
        'Message': 'Client.UserInitiatedShutdown: User initiated shutdown'
      },
      'Tags': [{
        'Key': 'Betriebssystem',
        'Value': 'Ubuntu'
      }, {
        'Key': 'Name',
        'Value': 'Secondary 2'
      }],
      'VirtualizationType': 'hvm',
      'CpuOptions': {
        'CoreCount': 1,
        'ThreadsPerCore': 1
      },
      'CapacityReservationSpecification': {
        'CapacityReservationPreference': 'open'
      },
      'HibernationOptions': {
        'Configured': False
      }
    }],
    'OwnerId': '032304311013',
    'ReservationId': 'r-066be12167c13ccce'
  }, {
    'Groups': [],
    'Instances': [{
      'AmiLaunchIndex': 0,
      'ImageId': 'ami-02df9ea15c1778c9c',
      'InstanceId': 'i-0377583959cef9d8d',
      'InstanceType': 't2.small',
      'KeyName': 'BFITest',
      'LaunchTime': datetime.datetime(2019, 11, 19, 12, 19, 42, tzinfo =
      tzutc()),
      'Monitoring': {
        'State': 'disabled'
      },
      'Placement': {
        'AvailabilityZone': 'eu-west-1b',
        'GroupName': '',
        'Tenancy': 'default'
      },
      'PrivateDnsName': 'ip-172-31-46-150.eu-west-1.compute.internal',
      'PrivateIpAddress': '172.31.46.150',
      'ProductCodes': [],
      'PublicDnsName': '',
      'State': {
        'Code': 80,
        'Name': 'stopped'
      },
      'StateTransitionReason': 'User initiated (2019-11-19 12:56:26 GMT)',
      'SubnetId': 'subnet-ea76a2b2',
      'VpcId': 'vpc-a44de5c0',
      'Architecture': 'x86_64',
      'BlockDeviceMappings': [{
        'DeviceName': '/dev/sda1',
        'Ebs': {
          'AttachTime': datetime.datetime(2019, 10, 25, 7, 27, 41, tzinfo =
          tzutc()),
          'DeleteOnTermination': True,
          'Status': 'attached',
          'VolumeId': 'vol-01fc3a826793967f6'
        }
      }, {
        'DeviceName': '/dev/sdf',
        'Ebs': {
          'AttachTime': datetime.datetime(2019, 11, 12, 20, 50, 43, tzinfo =
          tzutc()),
          'DeleteOnTermination': False,
          'Status': 'attached',
          'VolumeId': 'vol-0e9c3ff2c9ca673f1'
        }
      }],
      'ClientToken': '',
      'EbsOptimized': False,
      'EnaSupport': True,
      'Hypervisor': 'xen',
      'NetworkInterfaces': [{
        'Attachment': {
          'AttachTime': datetime.datetime(2019, 10, 25, 7, 27, 40, tzinfo =
          tzutc()),
          'AttachmentId': 'eni-attach-041ba4e206fc891e9',
          'DeleteOnTermination': True,
          'DeviceIndex': 0,
          'Status': 'attached'
        },
        'Description': '',
        'Groups': [{
          'GroupName': 'launch-wizard-9',
          'GroupId': 'sg-0d9c3489a8deecc92'
        }],
        'Ipv6Addresses': [],
        'MacAddress': '0a:3e:79:02:4f:ea',
        'NetworkInterfaceId': 'eni-06be67e8067cdbd7a',
        'OwnerId': '032304311013',
        'PrivateDnsName': 'ip-172-31-46-150.eu-west-1.compute.internal',
        'PrivateIpAddress': '172.31.46.150',
        'PrivateIpAddresses': [{
          'Primary': True,
          'PrivateDnsName': 'ip-172-31-46-150.eu-west-1.compute.internal',
          'PrivateIpAddress': '172.31.46.150'
        }],
        'SourceDestCheck': True,
        'Status': 'in-use',
        'SubnetId': 'subnet-ea76a2b2',
        'VpcId': 'vpc-a44de5c0',
        'InterfaceType': 'interface'
      }],
      'RootDeviceName': '/dev/sda1',
      'RootDeviceType': 'ebs',
      'SecurityGroups': [{
        'GroupName': 'launch-wizard-9',
        'GroupId': 'sg-0d9c3489a8deecc92'
      }],
      'SourceDestCheck': True,
      'StateReason': {
        'Code': 'Client.UserInitiatedShutdown',
        'Message': 'Client.UserInitiatedShutdown: User initiated shutdown'
      },
      'Tags': [{
        'Key': 'Name',
        'Value': 'Primary'
      }, {
        'Key': 'Betriebssystem',
        'Value': 'Ubuntu'
      }],
      'VirtualizationType': 'hvm',
      'CpuOptions': {
        'CoreCount': 1,
        'ThreadsPerCore': 1
      },
      'CapacityReservationSpecification': {
        'CapacityReservationPreference': 'open'
      },
      'HibernationOptions': {
        'Configured': False
      }
    }],
    'OwnerId': '032304311013',
    'ReservationId': 'r-037f3b6809995c7f8'
  }, {
    'Groups': [],
    'Instances': [{
      'AmiLaunchIndex': 0,
      'ImageId': 'ami-02df9ea15c1778c9c',
      'InstanceId': 'i-0cde3c6589b5b59d9',
      'InstanceType': 't2.small',
      'KeyName': 'BFITest',
      'LaunchTime': datetime.datetime(2019, 11, 19, 12, 19, 42, tzinfo =
      tzutc()),
      'Monitoring': {
        'State': 'disabled'
      },
      'Placement': {
        'AvailabilityZone': 'eu-west-1b',
        'GroupName': '',
        'Tenancy': 'default'
      },
      'PrivateDnsName': 'ip-172-31-37-227.eu-west-1.compute.internal',
      'PrivateIpAddress': '172.31.37.227',
      'ProductCodes': [],
      'PublicDnsName': '',
      'State': {
        'Code': 80,
        'Name': 'stopped'
      },
      'StateTransitionReason': 'User initiated (2019-11-19 12:56:26 GMT)',
      'SubnetId': 'subnet-ea76a2b2',
      'VpcId': 'vpc-a44de5c0',
      'Architecture': 'x86_64',
      'BlockDeviceMappings': [{
        'DeviceName': '/dev/sda1',
        'Ebs': {
          'AttachTime': datetime.datetime(2019, 10, 25, 7, 28, tzinfo =
          tzutc()),
          'DeleteOnTermination': True,
          'Status': 'attached',
          'VolumeId': 'vol-078b5bb6f2ca229e3'
        }
      }],
      'ClientToken': '',
      'EbsOptimized': False,
      'EnaSupport': True,
      'Hypervisor': 'xen',
      'NetworkInterfaces': [{
        'Attachment': {
          'AttachTime': datetime.datetime(2019, 10, 25, 7, 27, 59, tzinfo =
          tzutc()),
          'AttachmentId': 'eni-attach-07f1d6e7d4a20068c',
          'DeleteOnTermination': True,
          'DeviceIndex': 0,
          'Status': 'attached'
        },
        'Description': '',
        'Groups': [{
          'GroupName': 'launch-wizard-9',
          'GroupId': 'sg-0d9c3489a8deecc92'
        }],
        'Ipv6Addresses': [],
        'MacAddress': '0a:22:8e:fb:d6:4c',
        'NetworkInterfaceId': 'eni-03fdbbc6421605e04',
        'OwnerId': '032304311013',
        'PrivateDnsName': 'ip-172-31-37-227.eu-west-1.compute.internal',
        'PrivateIpAddress': '172.31.37.227',
        'PrivateIpAddresses': [{
          'Primary': True,
          'PrivateDnsName': 'ip-172-31-37-227.eu-west-1.compute.internal',
          'PrivateIpAddress': '172.31.37.227'
        }],
        'SourceDestCheck': True,
        'Status': 'in-use',
        'SubnetId': 'subnet-ea76a2b2',
        'VpcId': 'vpc-a44de5c0',
        'InterfaceType': 'interface'
      }],
      'RootDeviceName': '/dev/sda1',
      'RootDeviceType': 'ebs',
      'SecurityGroups': [{
        'GroupName': 'launch-wizard-9',
        'GroupId': 'sg-0d9c3489a8deecc92'
      }],
      'SourceDestCheck': True,
      'StateReason': {
        'Code': 'Client.UserInitiatedShutdown',
        'Message': 'Client.UserInitiatedShutdown: User initiated shutdown'
      },
      'Tags': [{
        'Key': 'Betriebssystem',
        'Value': 'Ubuntu'
      }, {
        'Key': 'Name',
        'Value': 'Secondary 1'
      }],
      'VirtualizationType': 'hvm',
      'CpuOptions': {
        'CoreCount': 1,
        'ThreadsPerCore': 1
      },
      'CapacityReservationSpecification': {
        'CapacityReservationPreference': 'open'
      },
      'HibernationOptions': {
        'Configured': False
      }
    }],
    'OwnerId': '032304311013',
    'ReservationId': 'r-02a22c528eebd1545'
  }],
  'ResponseMetadata': {
    'RequestId': 'be3e570a-972b-48b4-87c4-b6f7df6a1c87',
    'HTTPStatusCode': 200,
    'HTTPHeaders': {
      'content-type': 'text/xml;charset=UTF-8',
      'transfer-encoding': 'chunked',
      'vary': 'accept-encoding',
      'date': 'Mon, 25 Nov 2019 14:19:15 GMT',
      'server': 'AmazonEC2'
    },
    'RetryAttempts': 0
  }
}
"""
