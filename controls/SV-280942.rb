control 'SV-280942' do
  title 'RHEL 10 must remove all software components after updated versions have been installed.'
  desc <<~DESC
    Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by some adversaries.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 removes all software components after updated versions have been installed with the following command:

    $ sudo grep -i clean_requirements_on_remove /etc/dnf/dnf.conf
    clean_requirements_on_remove=True

    If "clean_requirements_on_remove" is not set to "True", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to remove all software components after updated versions have been installed.

    Edit the file "/etc/dnf/dnf.conf" by adding or editing the following line:

     clean_requirements_on_remove=True
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280942'
  tag rid: 'SV-280942r1165181_rule'
  tag stig_id: 'RHEL-10-200000'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-85408r1165180_fix'
  tag cci: ['CCI-002617']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -i clean_requirements_on_remove /etc/dnf/dnf.conf") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
