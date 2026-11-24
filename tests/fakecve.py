import copy
import json
from dataclasses import dataclass
from pathlib import Path, PurePath

JSONAny = None | bool | float | str | list["JSONAny"] | "JSONObject"
JSONObject = dict[str, "JSONAny"]

CVE_DIR = Path(__file__).with_name("cvedb")


@dataclass
class FakeCveApi:
    _records: JSONObject

    @classmethod
    def _from_files(cls, *sources: str | PurePath):
        records: JSONObject = {}
        for src_part in sources:
            src_path = (CVE_DIR / src_part).with_suffix(".json")
            with src_path.open("rb") as cve_src:
                cve_rec = json.load(cve_src)
            records[cve_rec["cveMetadata"]["cveId"]] = cve_rec
        return cls(records)

    def list_cves(self, *, state: str):
        for cve_rec in self._records.values():
            cve_meta = cve_rec["cveMetadata"]
            if cve_meta["state"] == state:
                yield {
                    "cve_id": cve_meta["cveId"],
                    "cve_year": cve_meta["dateReserved"][:4],
                    "owning_cna": "PSF",
                    "requested_by": {
                        "cna": "PSF",
                        "user": "python@example.org",
                    },
                    "reserved": cve_meta["dateReserved"],
                    "state": cve_meta["state"],
                    "time": {
                        "created": cve_meta["datePublished"],
                        "modified": cve_meta["dateUpdated"],
                    },
                }

    def show_cve_record(self, cve_id: str):
        # TODO: Convert KeyError into the right exception.
        return copy.deepcopy(self._records[cve_id])

    def update_published(
        self,
        *,
        cve_id: str,
        cve_json: JSONObject,
        validate: bool = True,
    ):
        try:
            is_published = self._records[cve_id]["cveMetadata"]["state"] == "PUBLISHED"
        except KeyError:
            is_published = False
        if is_published:
            self._records[cve_id] = cve_json
        else:
            raise ValueError(f"update_published on unpublished {cve_id}")
