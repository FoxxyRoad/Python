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
    parser.add_argument("-tn", "--table_name", action='store_true',
                        help="Name")
    parser.add_argument("-to", "--table_os", action='store_true', help="OS")
    parser.add_argument("-tp", "--table_p", action='store_true',
                        help="PatchDate")
    parser.add_argument("-tip", "--table_ip", action='store_true', help="IP")
    parser.add_argument("-td", "--table_d", action='store_true', help="Disk")
    parser.add_argument("-tit", "--table_it", action='store_true',
                        help="Instance Type")
    parser.add_argument("-ta", "--table_az", action='store_true',
                        help="Availability zone")
    parser.add_argument("-ts", "--table_sg", action='store_true',
                        help="Security Group")

    options = parser.parse_args(args)
    return options


options = getoptions(sys.argv[1:])

filters = []
header = []

if options.name is not None:
    filters.append({'Name': 'tag:Name', 'Values': [options.name]}, )
if options.table_name:
    header.append("Name")

if options.operating_system is not None:
    filters.append({'Name': 'tag:Betriebssystem', 'Values': \
        [options.operating_system]}, )
if options.table_os:
    header.append("Betriebssystem")

if options.patch_date is not None:
    filters.append({'Name': 'tag:PatchDate', 'Values': \
        [options.patch_date]}, )
if options.table_p:
    header.append("PatchDate")

if options.ip_address is not None:
    filters.append({'Name': 'private-ip-address', 'Values': \
        [options.ip_address]}, )
if options.table_ip:
    header.append("Private IP")

if options.disk is not None:
    filters.append({'Name': 'tag:DeviceName', 'Values': [options.disk]}, )
if options.table_d:
    header.append("Festplatten")

if options.instance_type is not None:
    filters.append({'Name': 'instance-type', 'Values': \
        [options.instance_type]}, )
if options.table_it:
    header.append("Instance Typ")

if options.availability_zone is not None:
    filters.append({'Name': 'availability-zone', 'Values': \
        [options.availability_zone]}, )
if options.table_az:
    header.append("Availability Zone")

if options.security_group is not None:
    filters.append({'Name': 'instance.group-name', 'Values': \
        [options.security_group]}, )
if options.table_sg:
    header.append("Security Group")


data = [header]
output = ec2.describe_instances(Filters=filters)
for reservation in output["Reservations"]:
    for instance in reservation["Instances"]:
        # Name
        input_name = ""
        for tags in instance["Tags"]:
            if tags["Key"] == 'Name':
                input_name += tags["Value"]

        # Betriebssystem
        input_os = ""
        for tags in instance["Tags"]:
            if tags["Key"] == 'Betriebssystem':
                input_os += tags["Value"]

        # PatchDate
        input_pd = ""
        for tags in instance["Tags"]:
            if tags["Key"] == 'PatchDate':
                input_pd += tags["Value"]

        # Groups
        input_sg = ""
        for group in instance["SecurityGroups"]:
            input_sg += group["GroupName"]

            if instance["SecurityGroups"][-1] != group:
                input_sg += " "

        # Festplatten
        input_fp = ""
        i = 0
        for DeviceName in instance["BlockDeviceMappings"]:
            input_fp += DeviceName["DeviceName"]
            i += 1

            if instance["BlockDeviceMappings"][-1] != DeviceName:
                input_fp += " | "

        row = []
        if "Name" in header:
            row.append(input_name)

        if "Betriebssystem" in header:
            row.append(input_os)

        if "PatchDate" in header:
            row.append(input_pd)

        if "Private IP" in header:
            row.append(instance["PrivateIpAddress"])

        if "Festplatten" in header:
            row.append(i)

        if "Instance Typ" in header:
            row.append(instance["InstanceType"])

        if "Availability Zone" in header:
            row.append(instance["Placement"]["AvailabilityZone"])

        if "Security Group" in header:
            row.append(input_sg)
        data.append(row)

table = terminaltables.AsciiTable(data)
print(table.table)
