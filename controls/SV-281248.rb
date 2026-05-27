control 'SV-281248' do
  title 'RHEL 10 must prevent special devices on nonroot local partitions.'
  desc <<~DESC
    The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

    The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is configured so that all nonroot local partitions are mounted with the "nodev" option with the following command:

    $ sudo mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'

    If any output is produced, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that "/etc/fstab" uses the "nodev" option on all nonroot local partitions.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281248'
  tag rid: 'SV-281248r1166696_rule'
  tag stig_id: 'RHEL-10-700200'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85714r1166695_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("mount | grep '^/dev\\S* on /\\S' | grep --invert-match 'nodev'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
