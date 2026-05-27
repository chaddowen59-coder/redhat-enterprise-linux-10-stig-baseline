control 'SV-281275' do
  title 'RHEL 10 must not allow unattended or automatic login via the graphical user interface.'
  desc <<~DESC
    Failure to restrict system access to authenticated users negatively impacts operating system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

    Verify RHEL 10 does not allow an unattended or automatic login to the system via a graphical user interface.

    Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:

    $  grep -i automaticlogin /etc/gdm/custom.conf
    AutomaticLoginEnable=false

    If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the GNOME desktop display manager disables automatic login.

    Update the "/etc/gdm/custom.conf" file to disable automatic login to the GNOME desktop:

    $ sudo vi /etc/gdm/custom.conf

    [daemon]
    AutomaticLoginEnable=false
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281275'
  tag rid: 'SV-281275r1166777_rule'
  tag stig_id: 'RHEL-10-700720'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85741r1166776_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("grep -i automaticlogin /etc/gdm/custom.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
