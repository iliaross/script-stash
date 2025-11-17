## Script Stash

A collection of useful scripts for sysadmin tasks, automation, and everyday
problem-solving. This is my personal toolbox of utilities I built over time.

### Scripts

#### Perl Scripts

- **check-apache-vhosts.pl**  
  Tests Apache virtual host configurations by enabling them one by one and
  verifying the configuration remains valid.
- **net-ip-lookup.pl**  
  Lookup comprehensive network information about an IP address or hostname
  including geolocation, ISP, ASN, timezone. Performs network diagnostics (ping,
  traceroute, port scanning).

#### Bash Scripts

- **hosts-update-segment.bash**  
  Recreates `/etc/hosts` entries for a specific segment block based on the
  template while keeping the rest of the file unchanged and saving a backup
  first.
- **hosts-sync.bash**  
  Syncs local Git projects to remote `debug-*` hosts defined in `/etc/hosts`,
  with specific support for Webmin and its modules, filtering by running virtual
  machine or domain patterns, and syncing either full projects or single files
  over `rsync`.
- **hosts-connect.bash**  
  Convenience wrapper around `ssh` to connect to `debug-*` hosts using short
  names, resolving the full hostname from `/etc/hosts` and reading the SSH
  password from an environment variable or standard input if needed.

### Requirements

Scripts might have different dependencies. Check the comments at the top of each
script for any specific requirements.

### Contributing

This is a personal collection, but if you find a bug or have a suggestion, feel
free to open an issue.

### License

MIT License
