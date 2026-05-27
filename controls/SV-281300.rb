control 'SV-281300' do
  title 'RHEL 10 must disable the ability of systemd to spawn an interactive boot process.'
  desc <<~DESC
    Using interactive or recovery boot, the console user could disable auditing, firewalls, or other services, weakening system security.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that the current GRUB 2 configuration disables the ability of systemd to spawn an interactive boot process with the following command:

    $ sudo grubby --info=ALL | grep args | grep 'systemd.confirm_spawn'

    If any output is returned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the current GRUB 2 configuration disables the ability of systemd to spawn an interactive boot process with the following command:

    $ sudo grubby --update-kernel=ALL --remove-args="systemd.confirm_spawn"
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281300'
  tag rid: 'SV-281300r1167050_rule'
  tag stig_id: 'RHEL-10-700980'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85766r1167049_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command("grubby --info=ALL | grep args | grep 'systemd.confirm_spawn'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
