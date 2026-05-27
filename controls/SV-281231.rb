control 'SV-281231' do
  title 'RHEL 10 must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS.'
  desc <<~DESC
    When an NFS server is configured to use RPCSEC_SYS, a selected userid and groupid are used to handle requests from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The RPCSEC_GSS method of authentication uses certificates on the server and client systems to more securely authenticate the remote mount request.
  DESC
  desc 'check', <<~CHECKTEXT
    Note: If no NFS mounts are configured, this requirement is not applicable.

    Verify RHEL 10 has the "sec" option configured for all NFS mounts with the following command:

    $ sudo grep nfs /etc/fstab
    192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5p:krb5i:krb5

    If the system is mounting file systems via NFS and has the sec option without the "krb5:krb5i:krb5p" settings, the "sec" option has the "sys" setting, or the "sec" option is missing, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 so that the "/etc/fstab" file "sec" option is defined for each NFS mounted file system, and the "sec" option does not have the "sys" setting.

    Ensure the "sec" option is defined as "krb5p:krb5i:krb5".
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281231'
  tag rid: 'SV-281231r1166645_rule'
  tag stig_id: 'RHEL-10-700115'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85697r1166644_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep nfs /etc/fstab") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
