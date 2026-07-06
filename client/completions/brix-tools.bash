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
    --io-uring --cksum --compress --zip --zip-append --streams --tpc
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
      ls|du|df) COMPREPLY=($(compgen -W "$conn_opts --human --json" -- "$cur")) ;;
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
  _brix_opts_filter "--tls --notlsok --noverifyhost --auth --wire-trace --timing
    --version --json --interval --count --prometheus --sweep --davs
    --cluster-url --probe-timeout --playback -S"
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

_xrdstorascan() {
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "verify bench dump fill compare" \
      -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  _brix_opts_filter "--algo --op --block --parallel --duration --count --pattern
    --json --summary --path --password --insecure -q"
}

complete -F _xrdcp xrdcp
complete -F _xrdfs xrdfs
complete -F _xrddiag xrddiag
complete -F _xrdcksum xrdcksum
complete -F _xrd xrd
complete -F _xrdprep xrdprep
complete -F _xrdgsiproxy xrdgsiproxy
complete -F _xrdsssadmin xrdsssadmin
complete -F _xrootdfs xrootdfs
complete -F _brixmount brixMount
complete -F _xrdstorascan xrdstorascan
