from src.core.models import Finding


def test_from_legacy_dict_coerces_invalid_related_location_coordinates_to_zero() -> None:
    finding = Finding.from_legacy_dict(
        {
            "type": "SQL_INJECTION",
            "file": "app.py",
            "line": 10,
            "related_locations": [
                {
                    "file_path": "app.py",
                    "start_line": None,
                    "start_character": None,
                    "message": "source",
                }
            ],
        }
    )

    assert len(finding.related_locations) == 1
    assert finding.related_locations[0].line == 0
    assert finding.related_locations[0].column == 0
