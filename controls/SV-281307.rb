control 'SV-281307' do
  title 'RHEL 10 must prevent the loading of a new kernel for later execution.'
  desc <<~DESC
    Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.

    Disabling kexec_load prevents an unsigned kernel image (that could be a windows kernel or modified vulnerable kernel) from being loaded. Kexec can be used to subvert the entire secureboot process and should be avoided at all costs, especially because it can load unsigned kernel images.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured to disable kernel image loading.

    Check the status of the "kernel.kexec_load_disabled" kernel parameter with the following command:

    $ sudo sysctl kernel.kexec_load_disabled
    kernel.kexec_load_disabled = 1

    If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable kernel image loading.

    Create a drop-in if it does not already exist:

    $ sudo vi /etc/sysctl.d/99-kernel_kexec_load_disabled.conf

    Add the following to the file:

    kernel.kexec_load_disabled = 1

    Reload settings from all system configuration files with the following command:

    $ sudo sysctl --system
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281307'
  tag rid: 'SV-281307r1184629_rule'
  tag stig_id: 'RHEL-10-701050'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-85773r1184628_fix'
  tag cci: ['CCI-003992']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe kernel_parameter('kernel.kexec_load_disabled') do
    its('value') { should cmp 1 }
  end
end
