class _BrokerDosScenario:
    """Exercise the broker under mixed mapped and rejected identity load."""

    identities = [
        ("alice", UID_ALICE),
        ("bob", UID_BOB),
        ("carol", UID_CAROL),
        ("dave", UID_DAVE),
        ("erin", UID_ERIN),
    ]
    denied = ["mallory", "lowu", "root"]

    def __init__(self, key, data, port):
        self.port = port
        self.pubdir = os.path.join(data, "pub")
        self.alice_dir = os.path.join(data, "alice")
        self.tokens = {name: mint(key, name) for name, _uid in self.identities}
        self.denied_tokens = {name: mint(key, name) for name in self.denied}
        self.expected_uids = dict(self.identities)
        self.created = []
        self.recovery_count = 0

    @staticmethod
    def uid_of_path(path):
        try:
            return os.lstat(path).st_uid
        except OSError:
            return -1

    @staticmethod
    def rm_quiet(path):
        try:
            os.unlink(path)
        except OSError:
            pass

    @staticmethod
    def run_thread_waves(threads):
        for base in range(0, len(threads), 8):
            wave = threads[base:base + 8]
            for thread in wave:
                thread.start()
            for thread in wave:
                thread.join()

    def recover(self, label):
        self.recovery_count += 1
        name = f"bdr_rec_{self.recovery_count}.txt"
        rel = f"/alice/{name}"
        body = f"rec-{self.recovery_count}-{label[:10]}".encode()
        put_status, _ = http("PUT", rel, self.port, self.tokens["alice"], body)
        get_status, received = http("GET", rel, self.port, self.tokens["alice"])
        path = os.path.join(self.alice_dir, name)
        owned = os.path.exists(path) and os.stat(path).st_uid == UID_ALICE
        healthy = all((
            put_status in (200, 201, 204),
            get_status == 200,
            received == body,
            owned,
        ))
        ok(
            healthy,
            f"recovery after {label}: alice roundtrip is owned 1001 "
            f"(PUT {put_status}, GET {get_status})",
        )

    def _record_churn_owner(self, bad, index, sub, expected, path):
        actual = self.uid_of_path(path)
        if actual != expected:
            bad.append((index, "owner", (sub, actual, expected)))
        if actual in (UID_SVC, 0):
            bad.append((index, "reserved-owner", (sub, actual)))

    @staticmethod
    def _record_churn_read(bad, served, index, sub, marker, responses):
        if len(responses) <= 1:
            bad.append((index, "crossed-read", (sub, -1)))
            return
        status, body = responses[1][:2]
        if status != 200 or body != marker:
            bad.append((index, "crossed-read", (sub, status)))
            return
        served[0] += 1

    def _finish_churn(self, bad, served, index, sub, expected, marker, responses):
        path = os.path.join(self.pubdir, f"bdr_churn_{sub}_{index}.txt")
        self.created.append(path)
        if not responses or responses[0][0] not in (200, 201, 204):
            status = responses[0][0] if responses else -1
            bad.append((index, "put-status", status))
            return
        self._record_churn_owner(bad, index, sub, expected, path)
        self._record_churn_read(bad, served, index, sub, marker, responses)

    def _churn_job(self, index, bad, served):
        sub, expected = self.identities[index % len(self.identities)]
        name = f"bdr_churn_{sub}_{index}.txt"
        marker = f"CHURN-{sub}-{index}-MARK\n".encode()
        sequence = [
            ("PUT", f"/pub/{name}", self.tokens[sub], marker, None),
            ("GET", f"/pub/{name}", self.tokens[sub], None, None),
        ]
        try:
            responses = http_keepalive(sequence, self.port)
        except Exception as error:  # noqa: BLE001
            bad.append((index, "exc", repr(error)))
            return
        self._finish_churn(bad, served, index, sub, expected, marker, responses)

    def _owner_observed(self, sub, expected):
        position = [name for name, _uid in self.identities].index(sub)
        for index in range(position, 24, len(self.identities)):
            path = os.path.join(self.pubdir, f"bdr_churn_{sub}_{index}.txt")
            if self.uid_of_path(path) == expected:
                return True
        return False

    def run_churn(self):
        bad = []
        served = [0]
        threads = [
            threading.Thread(target=self._churn_job, args=(index, bad, served))
            for index in range(24)
        ]
        self.run_thread_waves(threads)
        ok(
            not bad,
            "5-identity churn: each file kept its driving identity "
            f"(bad={bad[:3]})",
        )
        ok(served[0] == 24, f"5-identity churn served {served[0]}/24 jobs")
        owners = {
            expected
            for sub, expected in self.identities
            if self._owner_observed(sub, expected)
        }
        expected = {uid for _sub, uid in self.identities}
        ok(owners == expected, f"all mapped owners observed (seen={sorted(owners)})")
        self.recover("five-identity churn")

    def _switch_sequence(self):
        sequence = []
        order = [sub for sub, _uid in self.identities] * 2
        for index, sub in enumerate(order):
            name = f"bdr_sw_{sub}_{index}.txt"
            body = f"SW-{sub}-{index}\n".encode()
            sequence.append(("PUT", f"/pub/{name}", self.tokens[sub], body, None))
            sequence.append(("GET", f"/pub/{name}", self.tokens[sub], None, None))
            self.created.append(os.path.join(self.pubdir, name))
        return order, sequence

    def _switch_errors(self, order, responses):
        owner_bad = 0
        read_bad = 0
        for index, sub in enumerate(order):
            path = os.path.join(self.pubdir, f"bdr_sw_{sub}_{index}.txt")
            if self.uid_of_path(path) != self.expected_uids[sub]:
                owner_bad += 1
            response_index = index * 2 + 1
            expected = f"SW-{sub}-{index}\n".encode()
            if not self._response_matches(responses, response_index, expected):
                read_bad += 1
        return owner_bad, read_bad

    @staticmethod
    def _response_matches(responses, index, expected):
        if index >= len(responses):
            return False
        status, body = responses[index][:2]
        return status == 200 and body == expected

    def run_switch(self):
        order, sequence = self._switch_sequence()
        responses = http_keepalive(sequence, self.port)
        owner_bad, read_bad = self._switch_errors(order, responses)
        ok(owner_bad == 0, f"rapid switch ownership failures: {owner_bad}")
        ok(read_bad == 0, f"rapid switch read failures: {read_bad}")
        self.recover("rapid identity-switch")

    def _fair_denied_job(self, index, denied_created):
        sub = self.denied[(index // 2) % len(self.denied)]
        name = f"bdr_fair_d_{sub}_{index}.txt"
        body = f"{sub.upper()}-DENY-{index}\n".encode()
        status, _ = http(
            "PUT", f"/pub/{name}", self.port, self.denied_tokens[sub], body
        )
        path = os.path.join(self.pubdir, name)
        self.created.append(path)
        if status in (200, 201, 204) or os.path.exists(path):
            denied_created.append((sub, index, status, self.uid_of_path(path)))

    def _fair_legit_job(self, index, legit_bad, legit_done):
        sub, expected = self.identities[(index // 2) % len(self.identities)]
        name = f"bdr_fair_l_{sub}_{index}.txt"
        body = f"LEGIT-{sub}-{index}\n".encode()
        status, _ = http("PUT", f"/pub/{name}", self.port, self.tokens[sub], body)
        path = os.path.join(self.pubdir, name)
        self.created.append(path)
        good = all((
            status in (200, 201, 204),
            os.path.exists(path),
            self.uid_of_path(path) == expected,
        ))
        if not good:
            legit_bad.append((sub, index, status, self.uid_of_path(path)))
            return
        legit_done[0] += 1

    def _fair_job(self, index, denied_created, legit_bad, legit_done, exceptions):
        try:
            if index % 2 == 0:
                self._fair_denied_job(index, denied_created)
            else:
                self._fair_legit_job(index, legit_bad, legit_done)
        except Exception as error:  # noqa: BLE001
            exceptions.append((index, repr(error)))

    def run_fairness(self):
        denied_created = []
        legit_bad = []
        legit_done = [0]
        exceptions = []
        args = (denied_created, legit_bad, legit_done, exceptions)
        threads = [
            threading.Thread(target=self._fair_job, args=(index, *args))
            for index in range(24)
        ]
        self.run_thread_waves(threads)
        ok(not denied_created, f"denied principals created files: {denied_created[:3]}")
        ok(not legit_bad, f"legitimate operations failed: {legit_bad[:3]}")
        ok(legit_done[0] == 12, f"legitimate operations completed: {legit_done[0]}/12")
        ok(not exceptions, f"mixed-load exceptions: {exceptions[:2]}")
        self.recover("mixed legit+denied flood")

    def _stage_big_file(self):
        content = b"H" * (64 * 1024)
        rel = "/alice/bdr_big.bin"
        status, _ = http("PUT", rel, self.port, self.tokens["alice"], content)
        path = os.path.join(self.alice_dir, "bdr_big.bin")
        staged = all((
            status in (200, 201, 204),
            os.path.exists(path),
            os.stat(path).st_uid == UID_ALICE,
            os.path.getsize(path) == len(content),
        ))
        ok(staged, f"head-of-line fixture staged (PUT {status})")
        return rel, content

    def _big_read(self, rel, result):
        started = time.time()
        status, body = http("GET", rel, self.port, self.tokens["alice"])
        result["r"] = (status, len(body or b""), time.time() - started)

    def _small_op(self, sub, big_rel, propfind, results):
        started = time.time()
        rel = big_rel if sub == "alice" else "/pub"
        status, _body = http(
            "PROPFIND",
            rel,
            self.port,
            self.tokens[sub],
            hdrs={"Depth": "0", "Content-Type": "application/xml"},
            data=propfind,
        )
        results[sub] = (status, status in (207, 200), time.time() - started)

    def _run_hol_threads(self, big_rel, propfind, big_result, small_results):
        big_thread = threading.Thread(target=self._big_read, args=(big_rel, big_result))
        small_threads = [
            threading.Thread(
                target=self._small_op,
                args=(sub, big_rel, propfind, small_results),
            )
            for sub, _uid in self.identities
        ]
        big_thread.start()
        for thread in small_threads:
            thread.start()
        big_thread.join()
        for thread in small_threads:
            thread.join()

    @staticmethod
    def _assert_big_read(result, expected_length):
        status, length, _elapsed = result.get("r", (-1, 0, 99.0))
        ok(status == 200 and length == expected_length, f"large GET returned {length} bytes")

    @staticmethod
    def _assert_small_reads(results):
        all_good = all(value[1] for value in results.values())
        status_view = sorted((sub, value[0]) for sub, value in results.items())
        ok(len(results) == 5 and all_good, f"metadata results: {status_view}")

    @staticmethod
    def _assert_small_read_latency(results):
        slowest = max((value[2] for value in results.values()), default=99.0)
        ok(slowest < 6.0, f"slowest metadata operation: {slowest:.2f}s")
        alice_result = results.get("alice", (-1, False, 0))
        ok(alice_result[1], f"alice metadata status: {alice_result[0]}")

    def run_head_of_line(self):
        big_rel, content = self._stage_big_file()
        propfind = (
            b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
            b"<D:displayname/></D:prop></D:propfind>"
        )
        big_result = {}
        small_results = {}
        self._run_hol_threads(big_rel, propfind, big_result, small_results)
        self._assert_big_read(big_result, len(content))
        self._assert_small_reads(small_results)
        self._assert_small_read_latency(small_results)
        self.recover("head-of-line big-vs-small")

    def _final_alice_roundtrip(self):
        body = b"BROKER-SURVIVED-PRESSURE\n"
        put_status, _ = http(
            "PUT", "/alice/bdr_final.txt", self.port, self.tokens["alice"], body
        )
        get_status, received = http(
            "GET", "/alice/bdr_final.txt", self.port, self.tokens["alice"]
        )
        path = os.path.join(self.alice_dir, "bdr_final.txt")
        healthy = all((
            put_status in (200, 201, 204),
            get_status == 200,
            received == body,
            os.path.exists(path),
            os.stat(path).st_uid == UID_ALICE,
        ))
        ok(healthy, f"post-pressure alice roundtrip (PUT {put_status}, GET {get_status})")

    def _final_carol_write(self):
        name = "bdr_final_carol.txt"
        status, _ = http(
            "PUT", f"/pub/{name}", self.port, self.tokens["carol"], b"carol-after\n"
        )
        path = os.path.join(self.pubdir, name)
        self.created.append(path)
        ok(
            status in (200, 201, 204) and self.uid_of_path(path) == UID_CAROL,
            f"post-pressure carol mapping (HTTP {status}, uid={self.uid_of_path(path)})",
        )

    def _residue_entry(self, name):
        if not name.startswith("bdr_"):
            return None
        path = os.path.join(self.pubdir, name)
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                return None
            uid = os.lstat(path).st_uid
        except OSError:
            return None
        if uid < 1000 or uid == UID_SVC:
            return name, uid
        return None

    def _reserved_residue(self):
        try:
            names = os.listdir(self.pubdir)
        except OSError:
            return []
        residue = []
        for name in names:
            entry = self._residue_entry(name)
            if entry is not None:
                residue.append(entry)
        return residue

    def run_post_pressure(self):
        self._final_alice_roundtrip()
        self._final_carol_write()
        residue = self._reserved_residue()
        ok(not residue, f"reserved ownership residue: {residue[:4]}")
        for path in set(self.created):
            self.rm_quiet(path)
        self.recover("post-pressure final sanity")

    def run(self):
        self.recover("baseline")
        self.run_churn()
        self.run_switch()
        self.run_fairness()
        self.run_head_of_line()
        self.run_post_pressure()


def run_broker_dos_resilience(key, data, port, s3port):
    """Verify broker isolation and liveness under bounded concurrent pressure."""
    del s3port
    _BrokerDosScenario(key, data, port).run()
