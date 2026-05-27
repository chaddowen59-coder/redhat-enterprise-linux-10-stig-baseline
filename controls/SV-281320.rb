control 'SV-281320' do
  title 'RHEL 10 must disable acquiring, saving, and processing core dumps.'
  desc <<~DESC
    A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If kernel dumps are disabled in accordance with RHEL-10-701090, this requirement is not applicable.

    Verify RHEL 10 is not configured to acquire, save, or process core dumps with the following command:

    $ sudo systemctl status systemd-coredump.socket
    o systemd-coredump.socket
        Loaded: masked (Reason: Unit systemd-coredump.socket is masked.)
        Active: inactive (dead)
        ...

    If the "systemd-coredump.socket" is loaded and not masked, and the need for core dumps is not documented with the information system security officer as an operational requirement, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable the systemd-coredump.socket with the following command:

    $ sudo systemctl mask --now systemd-coredump.socket
    Created symlink /etc/systemd/system/systemd-coredump.socket -> /dev/null

    Reload the daemon for this change to take effect.

    $ sudo systemctl daemon-reload
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281320'
  tag rid: 'SV-281320r1184635_rule'
  tag stig_id: 'RHEL-10-701180'
  tag gtitle: 'SRG-OS-000312-GPOS-00124'
  tag fix_id: 'F-85786r1167109_fix'
  tag cci: ['CCI-002165']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe service('systemd-coredump.socket') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
