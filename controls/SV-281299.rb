control 'SV-281299' do
  title 'RHEL 10 must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc <<~DESC
    A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed operating system environment, this can create the risk of short-term loss of systems availability due to unintentional reboot. 

    In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is not configured to reboot the system when Ctrl-Alt-Delete is pressed with the following command:

    $ sudo systemctl status ctrl-alt-del.target
    o ctrl-alt-del.target
            Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
            Active: inactive (dead)

    If the "ctrl-alt-del.target" is loaded and not masked, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to disable the "ctrl-alt-del.target" with the following command:

    $ sudo systemctl disable --now ctrl-alt-del.target
    $ sudo systemctl mask --now ctrl-alt-del.target
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281299'
  tag rid: 'SV-281299r1166849_rule'
  tag stig_id: 'RHEL-10-700960'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-85765r1166848_fix'
  tag cci: ['CCI-002235']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe service('ctrl-alt-del.target') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
