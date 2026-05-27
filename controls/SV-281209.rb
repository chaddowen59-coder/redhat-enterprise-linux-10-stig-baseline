control 'SV-281209' do
  title 'RHEL 10 must require reauthentication when using the "sudo" command.'
  desc <<~DESC
    Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

    When operating systems provide the capability to escalate a functional capability, it is critical that the organization requires the user to reauthenticate when using the "sudo" command.

    If the value is set to an integer less than "0", the user's time stamp will not expire, and the user will not have to reauthenticate for privileged actions until the user's session is terminated.

    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 requires reauthentication when using the "sudo" command to elevate privileges with the following command:

    $ sudo grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/
    /etc/sudoers:Defaults timestamp_timeout=0

    If results are returned from more than one file location, this is a finding.

    If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to reauthenticate "sudo" commands after the specified timeout.

    Add the following line to "/etc/sudoers" or a file in "/etc/sudoers.d":

    Defaults timestamp_timeout=0
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281209'
  tag rid: 'SV-281209r1166579_rule'
  tag stig_id: 'RHEL-10-600540'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-85675r1166578_fix'
  tag cci: ['CCI-002038']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/sudoers') do
    it { should exist }
    its('content') { should match(/timestamp_timeout/i) }
  end
end
