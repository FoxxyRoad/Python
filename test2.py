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
    parser.add_argument("-tall", "--table_all",  action='store_true',
                        help="All tables")
    parser.add_argument("-tn", "--table_name", action='store_true',
                        help="Name")
    parser.add_argument("-to", "--table_os",  action='store_true', help="OS")
    parser.add_argument("-tp", "--table_p",  action='store_true',
                        help="PatchDate")
    parser.add_argument("-tip", "--table_ip",  action='store_true', help="IP")
    parser.add_argument("-td", "--table_d",  action='store_true', help="Disk")
    parser.add_argument("-tit", "--table_it", action='store_true',
                        help="Instance Type")
    parser.add_argument("-ta", "--table_az",  action='store_true',
                        help="Availability zone")
    parser.add_argument("-ts", "--table_sg",  action='store_true',
                        help="Security Group")

    options = parser.parse_args(args)
    return options


options = getoptions(sys.argv[1:])


filters = []

for instance_type in vars(options):
    if options.instance_type is not None:
        filters.append({'Name': 'instance-type', 'Values': \
            [options.instance_type]}, )
        break

for name in vars(options):
    if options.name is not None:
        filters.append({'Name': 'tag:Name', 'Values': [options.name]}, )
        break

for operating_system in vars(options):
    if options.operating_system is not None:
        filters.append({'Name': 'tag:Betriebssystem', 'Values': \
            [options.operating_system]}, )
        break

for patch_date in vars(options):
    if options.patch_date is not None:
        filters.append({'Name': 'tag:PatchDate', 'Values': \
            [options.patch_date]}, )
        break

for ip_address in vars(options):
    if options.ip_address is not None:
        filters.append({'Name': 'private-ip-address', 'Values': \
            [options.ip_address]}, )
        break

for disk in vars(options):
    if options.disk is not None:
        filters.append({'Name': 'tag:DeviceName', 'Values': [options.disk]}, )
        break

for availability_zone in vars(options):
    if options.availability_zone is not None:
        filters.append({'Name': 'availability-zone', 'Values': \
            [options.availability_zone]}, )
        break

for security_group in vars(options):
    if options.security_group is not None:
        filters.append({'Name': 'instance.group-name', 'Values': \
            [options.security_group]}, )
        break

data = []
table = terminaltables.AsciiTable(data)

output = ec2.describe_instances(Filters=filters)

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
title = []
for table_name in vars(options):
    if options.table_name is not False:
        title.append('Name')
        row.append(input_name)
        break
for table_os in vars(options):
    if options.table_os is not False:
        title.append("Betriebssystem")
        row.append(input_fp)
        break
for table_pd in vars(options):
    if options.table_p is not False:
        title.append("PatchDate")
        row.append(input_pd)
        break
for table_ip in vars(options):
    if options.table_ip is not False:
        title.append("Private IP")
        row.append(instance["PrivateIpAddress"])
        break
for table_d in vars(options):
    if options.table_d is not False:
        title.append("Festplatten")
        row.append(input_fp)
        break
for table_instance in vars(options):
    if options.table_it is not False:
        title.append('Instance Typ')
        row.append(instance["InstanceType"])
        break
for table_az in vars(options):
    if options.table_az is not False:
        title.append("Availability Zone")
        row.append(instance["Placement"]["AvailabilityZone"])
        break
for table_sg in vars(options):
    if options.table_sg is not False:
        title.append("Security Group")
        row.append(input_sg)
        break
data.append(title)
data.append(row)
print(table.table)
