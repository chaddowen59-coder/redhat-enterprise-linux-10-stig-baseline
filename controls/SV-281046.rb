control 'SV-281046' do
  title 'RHEL 10 must be configured so that all system device files are correctly labeled to prevent unauthorized modification.'
  desc <<~DESC
    If an unauthorized or modified device is allowed to exist on the system, the system may perform unintended or unauthorized operations.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that all system device files are correctly labeled to prevent unauthorized modification.

    List all device files on the system that are incorrectly labeled with the following commands:

    Note: Device files are normally found under "/dev", but applications may place device files in other directories and may necessitate a search of the entire system.

    $ sudo find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"

    $ sudo find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"

    Note: There are device files, such as "/dev/vmci", that are used when the operating system is a host virtual machine. They will not be owned by a user on the system and require the "device_t" label to operate. These device files are not a finding.

    If there is output from either of these commands, other than already noted, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that all system device files are correctly labeled to prevent unauthorized modification.

    Restore the SELinux policy for the affected device file from the system policy database using the following command:

    $ sudo restorecon -v <device_path>

    Substitute "<device_path>" with the path to the affected device file (from the output of the previous commands). An example device file path would be "/dev/ttyUSB0". 

    If the output of the above command does not indicate that the device was relabeled to a more specific SELinux type label, the SELinux policy of the system must be updated with more specific policy for the device class specified. 

    If a package was used to install support for a device class, that package could be reinstalled using the following command:

    $ sudo dnf reinstall <package_name>

    If a package was not used to install the SELinux policy for a given device class, it must be generated manually and provide specific type labels.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281046'
  tag rid: 'SV-281046r1165493_rule'
  tag stig_id: 'RHEL-10-400145'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85512r1165492_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find /dev -context *:device_t:* \\( -type c -o -type b \\) -printf \"%p %Z\\n\"") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
