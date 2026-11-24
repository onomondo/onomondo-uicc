# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(utils_test LIBS uicc)

if(TARGET utils)
	# Test of general utils functions, different from uicc helper functions
	ss_add_test(profile_decode_test LIBS uicc utils)

	#Test of profile provisioning
	ss_add_test(profile_provision_test FILES LIBS uicc utils storage)
endif(TARGET utils)
