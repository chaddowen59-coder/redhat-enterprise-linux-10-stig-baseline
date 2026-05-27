control 'SV-280952' do
  title 'RHEL 10 must have the "subscription-manager" package installed.'
  desc <<~DESC
    The Red Hat Subscription Manager application manages software subscriptions and software repositories for installed software products on the local system. It communicates with backend servers, such as the Red Hat Customer Portal or an on-premise instance of Subscription Asset Manager, to register the local system and grant access to software resources determined by the subscription entitlement.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the system is not an internet connected system, this requirement is not applicable.

    Verify RHEL 10 has the "subscription-manager" package installed with the following command:

    $ sudo dnf list --installed subscription-manager
    Installed Packages
    subscription-manager.x86_64                      1.30.6.1-1.el10_0                       @rhel-10-for-x86_64-baseos-rpms

    If the "subscription-manager" package is not installed, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to have the "subscription-manager" package installed with the following command:

    $ sudo dnf -y install subscription-manager
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-280952'
  tag rid: 'SV-280952r1195340_rule'
  tag stig_id: 'RHEL-10-200500'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-85418r1165210_fix'
  tag cci: ['CCI-003992']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe package('subscription-manager') do
    it { should_not be_installed }
  end
end
