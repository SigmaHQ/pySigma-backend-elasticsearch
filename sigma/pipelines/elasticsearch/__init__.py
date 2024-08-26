from .windows import ecs_windows, ecs_windows_old
from .zeek import ecs_zeek_beats, ecs_zeek_corelight, zeek_raw
from .kubernetes import ecs_kubernetes

pipelines = {
    "ecs_windows": ecs_windows,
    "ecs_windows_old": ecs_windows_old,
    "ecs_zeek_beats": ecs_zeek_beats,
    "ecs_zeek_corelight": ecs_zeek_corelight,
    "zeek": zeek_raw,
    "ecs_kubernetes": ecs_kubernetes, 
}
