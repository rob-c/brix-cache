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
  local sub="${COMP_WORDS[2]}"
  if [[ $COMP_CWORD -eq 2 ]]; then
    COMPREPLY=($(compgen -W "stat ls du df tree find mkdir rm rmdir mv chmod
      touch ln readlink truncate cat head tail wc grep hexdump dd upload
      download cmp cksum xattr readv writev locate query statvfs prepare
      stage evict explain" -- "${COMP_WORDS[COMP_CWORD]}"))
    return
  fi
  if [[ $COMP_CWORD -gt 2 ]]; then
    local global_opts="--tls --notlsok --noverifyhost --auth --token --version"
    case "$sub" in
      ls|du|df) _brix_opts_filter "--human $global_opts" ;;
      tree)     _brix_opts_filter "--dirs-only --depth $global_opts" ;;
      rm)       _brix_opts_filter "--verbose -r $global_opts" ;;
      touch)    _brix_opts_filter "--timestamp $global_opts" ;;
      *)        _brix_opts_filter "$global_opts" ;;
    esac
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

complete -F _xrdcp xrdcp
complete -F _xrdfs xrdfs
complete -F _xrddiag xrddiag
complete -F _xrdcksum xrdcksum
complete -F _xrd xrd
complete -F _xrdprep xrdprep
complete -F _xrdgsiproxy xrdgsiproxy
complete -F _xrdsssadmin xrdsssadmin
