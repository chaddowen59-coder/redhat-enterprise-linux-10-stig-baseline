control 'SV-281323' do
  title 'RHEL 10 must disable file system automount function unless required.'
  desc <<~DESC
    An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

    Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If the "autofs" service is not installed, this requirement is not applicable.

    Verify RHEL 10 is configured so that the file system automount function has been disabled with the following command:

    $ systemctl is-enabled  autofs
    masked

    If the returned value is not "masked", "disabled", or "not-found" and is not documented as an operational requirement with the information system security officer, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable the ability to automount devices.

    The "autofs" service can be disabled with the following command:

    $ sudo systemctl mask --now autofs.service
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281323'
  tag rid: 'SV-281323r1167119_rule'
  tag stig_id: 'RHEL-10-701210'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85789r1167118_fix'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe service('autofs.service') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
