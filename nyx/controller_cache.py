# Copyright 2011-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Cached controller queries to avoid repeated expensive get_info() calls that
raise exceptions, creating expensive memory allocations.
"""

import time

from nyx import tor_controller


class ControllerCache(object):
  """Namespace for cache state."""
  _address = None
  _address_time = 0
  _fingerprint = None
  _fingerprint_time = 0
  _exit_policy = None
  _exit_policy_time = 0


def get_address(default=None):
  """
  Provides our own address, utilizing a cache that's refreshed every 5 minutes.

  :param str default: value to return if we can't determine our address

  :returns: **str** with our address, or **default** if it can't be determined
  """

  controller = tor_controller()

  if time.time() - ControllerCache._address_time > 300:
    ControllerCache._address = controller.get_info('address', None)
    ControllerCache._address_time = time.time()

  return ControllerCache._address if ControllerCache._address is not None else default


def get_fingerprint(default=None):
  """
  Provides our own fingerprint, utilizing a cache that's refreshed every 5 minutes.

  :param str default: value to return if we can't determine our fingerprint

  :returns: **str** with our fingerprint, or **default** if it can't be determined
  """

  controller = tor_controller()

  if time.time() - ControllerCache._fingerprint_time > 300:
    ControllerCache._fingerprint = controller.get_info('fingerprint', None)
    ControllerCache._fingerprint_time = time.time()

  return ControllerCache._fingerprint if ControllerCache._fingerprint is not None else default


def get_exit_policy(default=None):
  """
  Provides our exit policy, utilizing a cache that's refreshed every 5 minutes.

  :param default: value to return if we can't determine our exit policy

  :returns: exit policy, or **default** if it can't be determined
  """

  controller = tor_controller()

  if time.time() - ControllerCache._exit_policy_time > 300:
    ControllerCache._exit_policy = controller.get_exit_policy(None)
    ControllerCache._exit_policy_time = time.time()

  return ControllerCache._exit_policy if ControllerCache._exit_policy is not None else default
