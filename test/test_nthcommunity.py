"""Unit tests for the nthcommunity module.

Test suite with functional unit tests for all classes and
methods, including direct interaction with the nth.community
platform API.
"""

import importlib
import sys
import oblivious
import unittest # pylint: disable=C0411

# Allow script to be invoked from the root directory of the source tree.
sys.path.append('.')

import nthcommunity # pylint: disable=C0413

# Maximum number of rows in a data set that can be contributed.
CONTRIBUTION_LENGTH_MAX = 10000

def api_exported():
    """
    API symbols that should be available to users upon module import.
    """
    return {
        'collaboration',
        'count', 'intersection',
        'integer', 'table',
        'contributor', 'recipient'
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
                []
                for _ in range(CONTRIBUTION_LENGTH_MAX)
            ]
        )
        self.assertTrue(isinstance(c, nthcommunity.table))

        # Test that limit cannot exceed module maximum.
        self.assertRaises(
            ValueError,
            lambda:\
                nthcommunity.table(
                    limit=CONTRIBUTION_LENGTH_MAX + 1
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
        table_b = [[oblivious.point.hash(str(i).encode()).to_base64()]for i in range(4, 12)]

        # Build a collaboration.
        c = nthcommunity.count(
            nthcommunity.intersection(
                nthcommunity.table(contributor=nthcommunity.contributor(), limit=10),
                nthcommunity.table(contributor=nthcommunity.contributor(), limit=10)
            )
        )

        # Generate contributor keys.
        cs = nthcommunity.recipient.generate(c)

        # Encrypt and contribute data.
        cs = {
            id_: nthcommunity.contributor.encrypt(c_, t)
            for ((id_, c_), t) in zip(cs.items(), [table_a, table_b])
        }

        # Evaluate the collaboration contributions to obtain a result.
        result = nthcommunity.recipient.evaluate(cs)
        self.assertEqual(
            result,
            {
                'type': 'integer',
                'value': len({row[0] for row in table_a} & {row[0] for row in table_b})
            }
        )

    def test_collaboration_errors(self):
        """
        Confirm recipient and contributor class methods enforce
        restrictions on collaboration workflows and other input
        parameters.
        """
        # Create simulated data tables.
        t = [[oblivious.point().to_base64()] for _ in range(200)]

        # Build a few collaborations (both supported and unsupported).
        unsupported = nthcommunity.count(
            nthcommunity.count(
                nthcommunity.table(
                    contributor=nthcommunity.contributor(),
                    limit=100
                )
            )
        )
        supported = nthcommunity.count(
            nthcommunity.intersection(
                nthcommunity.table(
                    contributor=nthcommunity.contributor(),
                    limit=100
                )
            )
        )

        # Generate contributor keys.
        unsupported = list(nthcommunity.recipient.generate(unsupported).values())[0]
        supported = list(nthcommunity.recipient.generate(supported).values())[0]

        # Try to contribute to an unsupported collaboration structures.
        self.assertRaises(
            ValueError,
            lambda: nthcommunity.contributor.encrypt(unsupported, t[:10])
        )
        unsupported["value"] = "intersection"
        self.assertRaises(
            ValueError,
            lambda: nthcommunity.contributor.encrypt(unsupported, t[:10])
        )
        unsupported["value"] = "count"
        unsupported["arguments"][0]["value"] = "intersection"
        unsupported["arguments"][0]["arguments"][0]["type"] = "operation"
        self.assertRaises(
            ValueError,
            lambda: nthcommunity.contributor.encrypt(unsupported, t[:10])
        )

        # Try to encrypt a contribution whose length exceeds what is
        # by the collaboration.
        self.assertRaises(
            ValueError,
            lambda: nthcommunity.contributor.encrypt(supported, t)
        )

if __name__ == "__main__":
    pass