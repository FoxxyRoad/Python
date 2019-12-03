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
    parser.add_argument("-tall", "--table_all", help="All tables")
    parser.add_argument("-tn", "--table_name", action='store_true',
                        help="Name")
    parser.add_argument("-to", "--table_os", help="OS")
    parser.add_argument("-tp", "--table_p", help="PatchDate")
    parser.add_argument("-tip", "--table_ip", help="IP")
    parser.add_argument("-td", "--table_d", help="Disk")
    parser.add_argument("-tit", "--table_it", action='store_true',
                        help="Instance Type")
    parser.add_argument("-ta", "--table_az", help="Availability zone")
    parser.add_argument("-ts", "--table_sg", help="Security Group")

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

output = ec2.describe_instances(Filters=filters)


def filtern():
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


data = []
table = terminaltables.AsciiTable(data)
row = []
for table_name in vars(options):
    if options.table_name is not False:
        data.append("Name")
        row.append(filtern.input_name)
        break

data.append(row)
print(table.table)
