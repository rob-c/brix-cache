# brix-tools.bash — bash completion for the brix client CLI suite.
# zsh: `autoload -U +X bashcompinit && bashcompinit`, then source this file.

_brix_opts_filter() {  # complete only when the current word starts with '-'
  local cur="${COMP_WORDS[COMP_CWORD]}"
  [[ "$cur" == -* ]] || return 1
  COMPREPLY=($(compgen -W "$1" -- "$cur"))
  return 0
}

_xrdcp() {
  local opts="-f -r -P --posc -s -v -d --verbose --debug -N --no-progress
    -n -j -S -T -V -h --from --retry --no-retry
    --max-stall --auto-refresh --oidc-account --jobs --sync --sync-check
    --delete --dry-run --exclude --include --remove-source --journal --resume
    --progress --verify --tls --notlsok --noverifyhost --auth --proxy --pgrw
    --io-uring --io-uring-direct --cksum --compress --zip --zip-append --streams --parallel --tpc
    --tpc-token-mode --token --s3-access --s3-secret --s3-region
    --wire-trace --timing"
  _brix_opts_filter "$opts" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --sync-check) COMPREPLY=($(compgen -W "size mtime cksum" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --tpc)        COMPREPLY=($(compgen -W "first only delegate" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --auth)       COMPREPLY=($(compgen -W "gsi ztn krb5 sss unix" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --io-uring)   COMPREPLY=($(compgen -W "on off auto" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --from|--journal|--proxy) COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
  COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
}

_xrdfs() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local conn_opts="--tls --notlsok --noverifyhost --auth -T --token --version"
  # Connection-level flags: complete whenever the current word starts with '-',
  # regardless of position (options can appear before the endpoint or subcommand).
  if [[ "$cur" == -* ]]; then
    local sub="${COMP_WORDS[2]}"
    case "$sub" in
      ls|du)    COMPREPLY=($(compgen -W "$conn_opts --human --json" -- "$cur")) ;;
      df)       COMPREPLY=($(compgen -W "$conn_opts --human" -- "$cur")) ;;
      tree)     COMPREPLY=($(compgen -W "$conn_opts --dirs-only --depth" -- "$cur")) ;;
      rm)       COMPREPLY=($(compgen -W "$conn_opts --verbose -r" -- "$cur")) ;;
      touch)    COMPREPLY=($(compgen -W "$conn_opts --timestamp" -- "$cur")) ;;
      upload|download) COMPREPLY=($(compgen -W "$conn_opts --io-uring" -- "$cur")) ;;
      *)        COMPREPLY=($(compgen -W "$conn_opts" -- "$cur")) ;;
    esac
    return
  fi
  if [[ $COMP_CWORD -eq 2 ]]; then
    COMPREPLY=($(compgen -W "stat ls du df tree find mkdir rm rmdir mv chmod
      touch ln readlink truncate cat head tail wc grep hexdump dd upload
      download cmp cksum xattr readv writev locate query statvfs prepare
      stage evict explain" -- "$cur"))
    return
  fi
}

_xrddiag() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "check bench metabench watch topology status
      compare remote-doctor probe-robustness replay srr tape qstats wait41
      mpxstats" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  _brix_opts_filter "--tls --notlsok --no-verify-tls --noverifyhost --auth
    --auth-suite --wire-trace --timing --version --json --full --interval
    --count --prometheus --sweep --davs --davs-tls --cluster-url
    --probe-timeout --timeout --playback --capture --vs-reference
    --i-am-authorized --allow-write --all-servers --cap-threshold
    --config-audit --deep-recon --latency --latency-count --map --map-format
    --metrics-port --tpc-target -S" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --map-format) COMPREPLY=($(compgen -W "ascii tree dot mermaid" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --auth)       COMPREPLY=($(compgen -W "gsi ztn krb5 sss unix" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --playback|--capture) COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
}

_xrdcksum() {
  local sub="${COMP_WORDS[1]}"
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "crc32c crc64 adler32 verify info tree check" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  case "$sub" in
    tree|check) _brix_opts_filter "--algo" && return ;;
  esac
  COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
}

_xrd() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "cp get put sync upload download
      ls stat du df tree find mkdir rm rmdir mv truncate
      cat head tail wc grep hexdump dd cmp cksum xattr
      touch chmod ln readlink stage evict locate query statvfs prepare explain
      diag ping certinfo clockskew whoami caps doctor login
      mount mounts unmount
      inventory verify drift inspect replicas
      version help" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
  fi
}

_xrdprep() {
  _brix_opts_filter "-s --stage -c --cancel -w --wmode -f --fresh -e --evict
    -p --priority -h --help --version"
}

_xrdgsiproxy() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "init info destroy --help --version" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  _brix_opts_filter "-valid --valid -cert --cert -key --key -out --out
    -bits --bits -file --file --help --version"
}

_xrdsssadmin() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "add install list del --help --version" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  _brix_opts_filter "-k --keytab --user --group --name --id --lifetime
    --keylen --help --version"
}

_xrootdfs() {
  _brix_opts_filter "--token --noverifyhost --tls --notlsok --auth --max-conns
    --version --streams --lazy-streams --max-stall --keepalive --max-retries
    --connect-timeout --io-timeout --attr-timeout --entry-timeout --kernel-cache
    --compress --readahead --writeback --xattr -f -d -s -o" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --auth)     COMPREPLY=($(compgen -W "gsi ztn unix" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --compress) COMPREPLY=($(compgen -W "gzip deflate zstd br xz bzip2" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
  COMPREPLY=($(compgen -d -- "${COMP_WORDS[COMP_CWORD]}"))
}

_brixmount() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    local cur="${COMP_WORDS[COMP_CWORD]}"
    if [[ "$cur" == -* ]]; then
      COMPREPLY=($(compgen -W "--overlay-list --overlay-reset --version" -- "$cur"))
    else
      COMPREPLY=($(compgen -W "cvmfs cvmfs-rw eos root roots" -- "$cur"))
    fi
    return
  fi
  _brix_opts_filter "--overlay-list --overlay-reset --version" && return
  COMPREPLY=($(compgen -d -- "${COMP_WORDS[COMP_CWORD]}"))
}

_brixcvmfs() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  # `repo` is the Stratum-0 release-manager surface; everything else is a mount.
  if [[ "${COMP_WORDS[1]}" == "repo" ]]; then
    case $COMP_CWORD in
      2) COMPREPLY=($(compgen -W "mkfs info resign transaction abort publish
           fsck gc tag" -- "$cur")) ;;
      3) [[ "${COMP_WORDS[2]}" == "tag" ]] \
           && COMPREPLY=($(compgen -W "add list rollback" -- "$cur")) \
           || COMPREPLY=($(compgen -d -- "$cur")) ;;
      *) case "${COMP_WORDS[2]}" in
           publish) _brix_opts_filter "--chunk-size --dirtab" && return ;;
           fsck)    _brix_opts_filter "--data" && return ;;
           gc)      _brix_opts_filter "--keep --keep-since --grace" && return ;;
           tag)     _brix_opts_filter "-m" && return ;;
         esac
         COMPREPLY=($(compgen -d -- "$cur")) ;;
    esac
    return
  fi
  if [[ $COMP_CWORD -eq 1 ]]; then
    [[ "$cur" == -* ]] \
      && COMPREPLY=($(compgen -W "--rw --check --prewarm --version" -- "$cur")) \
      || COMPREPLY=($(compgen -W "repo" -- "$cur"))
    return
  fi
  _brix_opts_filter "--rw --check --prewarm --version --overlay-list
    --overlay-reset -o -f -d" && return
  COMPREPLY=($(compgen -d -- "$cur"))
}

_xrdstorascan() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "verify bench dump fill compare" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  _brix_opts_filter "--algo --op --block --parallel --duration --count --pattern
    --json --summary --path --password --insecure -q"
}

_xrdceph_striper_migrate() {
  local opts="--mode --rollback --finalize --list --strip --threads --verify
    --delete-source --force --dry-run --conf --config --sample-mb --progress
    --json --state --prefix --match --help"
  _brix_opts_filter "$opts" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --mode) COMPREPLY=($(compgen -W "redirect copy" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --list|--conf|--config|--state) COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
  COMPREPLY=()
}

_xrdceph_cephfs_to_striper() {
  local opts="--assume-quiesced --report-only --rollback --finalize --strip
    --threads --verify --delete-source --dry-run --conf --config
    --json --state --list --prefix --match --progress --help"
  _brix_opts_filter "$opts" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --list|--conf|--config|--state) COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
  COMPREPLY=()
}

_brixfaultproxy() {
  local opts="--listen --target --control --bind --insecure-bind --max-conns
    --seed --script --quiet --latency --jitter --chunk --drip --rate --lossy
    --reorder --corrupt --dup --truncate-at --fail-nth --heal-after --hang
    --block --help --version -l -t -c -b -q -h -V
    --accept-pause --chaos --delay-first --drop-bytes --event-log --fanout
    --flap --global-rate --inject --mangle-len --max-lifetime --mss --preset
    --priv-iface --privileged --proxy-header --ramp --rcvbuf --repeat-bytes
    --replace --sndbuf --stall --trigger --trigger-once"
  _brix_opts_filter "$opts" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --bind|-b)  COMPREPLY=($(compgen -W "127.0.0.1 ::1 0.0.0.0" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --script|--event-log) COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
  COMPREPLY=()
}

_xrdrados_rescue() {
  if [[ $COMP_CWORD -eq 2 ]]; then
    COMPREPLY=($(compgen -W "ls stat get cp" -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
}

_xrdcephfs_rescue() {
  if [[ $COMP_CWORD -eq 3 ]]; then
    COMPREPLY=($(compgen -W "ls stat cat get cp" -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
}

complete -F _xrdcp xrdcp
complete -F _xrdfs xrdfs
complete -F _xrddiag xrddiag
complete -F _xrdcksum xrdcksum
complete -F _xrd xrd
complete -F _xrdprep xrdprep
complete -F _xrdgsiproxy xrdgsiproxy
complete -F _xrdsssadmin xrdsssadmin-brix
complete -F _xrootdfs xrootdfs
complete -F _brixmount brixMount
complete -F _brixcvmfs brixcvmfs
complete -F _xrdstorascan xrdstorascan
complete -F _brixfaultproxy brix-fault-proxy
complete -F _xrdceph_striper_migrate xrdceph_striper_migrate xrdceph_striper_migrate.py
complete -F _xrdceph_cephfs_to_striper xrdceph_cephfs_to_striper xrdceph_cephfs_to_striper.py
complete -F _xrdrados_rescue xrdrados_rescue
complete -F _xrdcephfs_rescue xrdcephfs_rescue
complete -o default xrdceph_migrate
