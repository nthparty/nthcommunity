"""
Test suite with functional unit tests for all classes and
methods, including direct interaction with the nth.community
platform API.
"""
import importlib
import sys
import base64
import oblivious
import unittest # pylint: disable=C0411

# Allow script to be invoked from the root directory of the source tree.
sys.path.append('.')

import nthcommunity # pylint: disable=C0413

# Upper bounds on table and table field sizes.
CONTRIBUTION_MAX_TABLE_LENGTH = 1000
CONTRIBUTION_MAX_TABLE_ROW_FIELD_LENGTH = 256

def api_exported():
    """
    API symbols that should be available to users upon module import.
    """
    return {
        'collaboration',
        'count', 'intersection', 'summation',
        'integer', 'table',
        'contributor', 'recipient',
        'ServiceError'
    }

class Test_namespace(unittest.TestCase):
    """
    Check that namespaces provide access to the expected
    classes and functions.
    """
    def test_init(self):
        """Confirm that methods corresponding to API are exported."""
        init = importlib.import_module('nthcommunity.__init__')
        self.assertTrue(api_exported().issubset(init.__dict__.keys()))

    def test_module(self):
        """Confirm that methods corresponding to API are present in module."""
        module = importlib.import_module('nthcommunity.nthcommunity')
        self.assertTrue(api_exported().issubset(module.__dict__.keys()))

class Test_nthcommunity(unittest.TestCase):
    """
    Wrapper class for tests of nthcommunity classes and methods.
    """
    def test_collaboration(self):
        """
        Test collaboration data structure classes.
        """
        c = nthcommunity.integer(value=123)
        self.assertTrue(isinstance(c, nthcommunity.integer))

        c = nthcommunity.table(
            value=[
                ['a']
                for _ in range(CONTRIBUTION_MAX_TABLE_LENGTH)
            ],
            _internal=True
        )
        self.assertTrue(isinstance(c, nthcommunity.table))

        # Test that limit cannot exceed module maximum.
        self.assertRaises(
            ValueError,
            lambda:\
                nthcommunity.table(
                    limit=CONTRIBUTION_MAX_TABLE_LENGTH + 1
                )
        )

        # Test that limit is enforced.
        self.assertRaises(
            ValueError,
            lambda:\
                nthcommunity.table(
                    limit=10,
                    value=[[''] for _ in range(20)]
                )
        )

    def test_collaboration_count_intersection(self):
        """
        Test recipient and contributor class methods using a
        collaboration workflow.
        """
        # Create simulated data tables.
        table_a = [[oblivious.point.hash(str(i).encode()).to_base64()] for i in range(0, 8)]
        table_b = [[oblivious.point.hash(str(i).encode()).to_base64()] for i in range(4, 12)]

        # Build a count-intersection collaboration.
        c = nthcommunity.count(
            nthcommunity.intersection(
                nthcommunity.table(contributor=nthcommunity.contributor(), limit=10),
                nthcommunity.table(contributor=nthcommunity.contributor(), limit=10)
            )
        )

        # Generate contributor keys.
        contributors_ = [nthcommunity.contributor() for _ in range(2)]
        recipient_ = nthcommunity.recipient()
        cs = recipient_.generate(c)

        # Test JSON conversion methods for contribution keys.
        cs = {
            k: nthcommunity.collaboration.from_json(v.to_json())
            for (k, v) in cs.items()
        }

        # Encrypt and contribute data.
        cs = {
            id_: contributors_[i].encrypt(c_, t)
            for (i, ((id_, c_), t)) in enumerate(zip(cs.items(), [table_a, table_b]))
        }

        # Test JSON conversion methods for encrypted contributions.
        cs = {
            k: nthcommunity.collaboration.from_json(v.to_json())
            for (k, v) in cs.items()
        }

        # Evaluate the collaboration contributions to obtain a result.
        result = recipient_.evaluate(cs)
        self.assertEqual(
            result,
            {
                'type': 'integer',
                'value': len({row[0] for row in table_a} & {row[0] for row in table_b})
            }
        )

        # Build an intersection collaboration.
        c = nthcommunity.intersection(
            nthcommunity.table(contributor=nthcommunity.contributor(), limit=10),
            nthcommunity.table(contributor=nthcommunity.contributor(), limit=10)
        )

        # Generate contributor keys.
        cs = recipient_.generate(c)

        # Encrypt and contribute data.
        cs = {
            id_: contributors_[i].encrypt(c_, t)
            for (i, ((id_, c_), t)) in enumerate(zip(cs.items(), [table_a, table_b]))
        }

        # Evaluate the collaboration contributions to obtain a result.
        result = recipient_.evaluate(cs)
        self.assertEqual(
            {row[0] for row in result["value"]},
            {row[0] for row in table_a} & {row[0] for row in table_b}
        )

    def test_collaboration_summation(self):
        """
        Test recipient and contributor class methods using a
        collaboration workflow.
        """
        # Create simulated inputs.
        number_a = 123
        number_b = 456

        # Build a summation collaboration.
        c = nthcommunity.summation(
            nthcommunity.integer(contributor=nthcommunity.contributor()),
            nthcommunity.integer(contributor=nthcommunity.contributor())
        )

        # Generate contributor keys.
        contributors_ = [nthcommunity.contributor() for _ in range(2)]
        recipient_ = nthcommunity.recipient()
        cs = recipient_.generate(c)

        # Test JSON conversion methods for contribution keys.
        cs = {
            k: nthcommunity.collaboration.from_json(v.to_json())
            for (k, v) in cs.items()
        }

        # Encrypt and contribute data.
        cs = {
            id_: contributors_[i].encrypt(c_, t)
            for (i, ((id_, c_), t)) in enumerate(zip(cs.items(), [number_a, number_b]))
        }

        # Test JSON conversion methods for encrypted contributions.
        cs = {
            k: nthcommunity.collaboration.from_json(v.to_json())
            for (k, v) in cs.items()
        }

        # Evaluate the collaboration contributions to obtain a result.
        result = recipient_.evaluate(cs)
        self.assertEqual(
            result,
            {
                'type': 'integer',
                'value': number_a + number_b
            }
        )

    def test_service_error(self):
        """
        Test an error response from the service API.
        """
        recipient_ = nthcommunity.recipient()
        contributor_ = nthcommunity.contributor()
        c = nthcommunity.summation(
            nthcommunity.integer(contributor=nthcommunity.contributor()),
            nthcommunity.integer(contributor=nthcommunity.contributor())
        )

        # Test service API response that explicitly indicates an error.
        self.assertRaises(
            nthcommunity.ServiceError,
            lambda: recipient_.evaluate({contributor_["identifier"]: c})
        )

    def test_collaboration_errors(self):
        """
        Confirm recipient and contributor class methods enforce
        restrictions on collaboration workflows and other input
        parameters.
        """
        # Create simulated data tables.
        t = [[oblivious.point().to_base64()] for _ in range(200)]

        # Build a structurally permitted collaboration.
        permitted = nthcommunity.count(
            nthcommunity.intersection(
                nthcommunity.table(
                    contributor=nthcommunity.contributor(),
                    limit=100
                ),
                nthcommunity.table(
                    contributor=nthcommunity.contributor(),
                    limit=100
                )
            )
        )

        # Build some collaborations that are not permitted according to their
        # structure. Note that some of these are only possible to construct
        # by overriding type checking within the collaboration constructors.
        unpermitted = [
            nthcommunity.count(
                nthcommunity.count(
                    nthcommunity.intersection(
                        nthcommunity.table(contributor=nthcommunity.contributor()),
                        nthcommunity.table(contributor=nthcommunity.contributor())
                    )
                ),
                _internal=True
            ),
            nthcommunity.table(
                contributor=nthcommunity.contributor(),
                limit=100
            ),
            nthcommunity.summation(
                nthcommunity.table(
                    contributor=nthcommunity.contributor()
                ),
                nthcommunity.integer(contributor=nthcommunity.contributor()),
                _internal=True
            ),
            nthcommunity.intersection(
                nthcommunity.intersection(
                    nthcommunity.table(contributor=nthcommunity.contributor()),
                    nthcommunity.table(contributor=nthcommunity.contributor())
                ),
                _internal=True
            )
        ]

        # Create contributors and recipient.
        contributor_ = nthcommunity.contributor()
        recipient_ = nthcommunity.recipient()

        # Try to contribute to collaborations that have unpermitted structures.
        for c in unpermitted:
            c = list(recipient_.generate(c).values())[0]
            self.assertRaises(
                ValueError,
                lambda c=c: contributor_.encrypt(c, t[:10])
            )

        # Try to contribute to a collaboration with an invalid certificate.
        unpermitted[0]["certificate"] = base64.standard_b64encode(bytes([0])).decode()
        self.assertRaises(
            RuntimeError,
            lambda: contributor_.encrypt(unpermitted[0], t[:10])
        )

        # Try to encrypt a contribution whose length exceeds what is
        # by the collaboration.
        permitted = list(recipient_.generate(permitted).values())[0]
        self.assertRaises(
            ValueError,
            lambda: contributor_.encrypt(permitted, t)
        )

        # Try to parse a collaboration from a JSON representation with missing
        # attributes.
        del permitted["type"]
        self.assertRaises(
            ValueError,
            lambda: nthcommunity.collaboration.from_json(permitted.to_json())
        )
        c = nthcommunity.contributor.from_json(nthcommunity.contributor().to_json())
        del c["identifier"]
        self.assertRaises(
            ValueError,
            lambda: nthcommunity.contributor.from_json(c.to_json())
        )
