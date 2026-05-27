control 'SV-281203' do
  title 'RHEL 10 must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc <<~DESC
    Operating system management includes the ability to control the number of users and user sessions that use an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service (DoS) attacks.

    This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 limits the number of concurrent sessions to "10" for all accounts and/or account types with the following command:

    $ sudo grep -rs maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf | grep -v '#'
    /etc/security/limits.d/maxlogins.conf:* hard maxlogins 10

    This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.

    If the "maxlogins" item is missing or commented out, or the value is set greater than "10" and is not documented with the information system security officer as an operational requirement for all domains that have the "maxlogins" item assigned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to limit the number of concurrent sessions to "10" for all accounts and/or account types.

    Add the following line to the top of "/etc/security/limits.conf" or in a ".conf" file defined in "/etc/security/limits.d/":

    * hard maxlogins 10
  FIXTEXT
  impact 0.3
  tag check_id: 'M'
  tag severity: 'low'
  tag gid: 'V-281203'
  tag rid: 'SV-281203r1166561_rule'
  tag stig_id: 'RHEL-10-600475'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-85669r1166560_fix'
  tag cci: ['CCI-000054']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/security/limits.d/maxlogins.conf') do
    it { should exist }
    its('content') { should match(/#/i) }
  end
end
