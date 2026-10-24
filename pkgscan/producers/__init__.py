from pkgscan.producers.code_diff import CodeDiff
from pkgscan.producers.code_rules import SemgrepRules, YaraRules
from pkgscan.producers.files import PackageFiles
from pkgscan.producers.known_iocs import KnownIOCs
from pkgscan.producers.lifecycle import LifecycleHooks, discover_entrypoints
from pkgscan.producers.metadata import PackageMetadata
from pkgscan.producers.network_iocs import NetworkIOCs
from pkgscan.producers.obfuscation_stats import ObfuscationStats
from pkgscan.producers.publisher import PublisherAccount
from pkgscan.producers.typosquat import Typosquatting

ALL_PRODUCERS = [
    PackageMetadata,  # 1
    PackageFiles,  # 2
    PublisherAccount,  # 3
    LifecycleHooks,  # 4
    SemgrepRules,  # 5.1-5.7
    YaraRules,  # 5.1 + 7
    ObfuscationStats,  # 5.1
    NetworkIOCs,  # 5.2
    CodeDiff,  # 6
    Typosquatting,  # 8
    KnownIOCs,
]

__all__ = ["ALL_PRODUCERS", "discover_entrypoints"]
