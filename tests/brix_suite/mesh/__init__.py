"""The two interop meshes — real XRootD and nginx-xrootd in one topology.

Seven modules moved one-to-one from the flat ``tests/`` tree at TS-5:
``cms_mesh_lib`` (plus its two continuation shards) owns the daemon
lifecycle, config builders and fixed port map for the CMS-mesh topologies;
``hybrid_mesh_lib`` reuses that launcher for the two-tier cross-backend
mesh; ``mesh_config`` renders the committed templates under
``tests/configs/mesh/``; and the two ``*_servers`` modules are the
``start``/``stop`` orchestrators the spec catalogue drives.

Nothing is imported here.  ``cms_mesh_lib`` runs :func:`shutil.which` five
times at import to discover ``xrootd``/``cmsd``/``xrdfs``/``xrdcp``/``curl``,
and the catalogue is careful to keep that off any module's top level — a
package ``__init__`` that pulled it in would put the cost back on every
importer of :mod:`brix_suite`.

Both meshes bind fixed, dedicated bands (cms-mesh 21610-21749, hybrid
11300-11330) rather than leasing from the lane's mock band, because a mesh
node's config names its peers by port: the numbers are part of the
topology, not an allocation.  That is why exactly one mesh of each kind
fits on a host, and why both specs carry ``allow_remote_skip=True``.
"""
