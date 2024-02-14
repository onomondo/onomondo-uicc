/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <onomondo/softsim/list.h>

/* A sample struct that can be organzied using a list */
struct list_test {
	struct ss_list list;
	int user_data;
};

static void add_iterate_and_remove_test(void)
{
	struct ss_list list;
	struct list_test a;
	struct list_test b;
	struct list_test c;
	struct list_test d;
	struct list_test e;
	struct list_test f;
	struct list_test *cursor;
	struct list_test *precursor;

	printf
	    ("TEST: Initialize a list, add some elements, iterate the list\n");

	a.user_data = 11;
	b.user_data = 22;
	c.user_data = 33;
	d.user_data = 1;
	e.user_data = 2;
	f.user_data = 3;

	/* Before we can do anything with the list, we must initialize it */
	ss_list_init(&list);

	/* Add some elements to the list */
	ss_list_put(&list, &a.list);
	ss_list_put(&list, &b.list);
	ss_list_put(&list, &c.list);
	ss_list_push(&list, &d.list);
	ss_list_push(&list, &e.list);
	ss_list_push(&list, &f.list);

	/* Iterate over the list */
	SS_LIST_FOR_EACH(&list, cursor, struct list_test, list) {
		printf(" user_data=%d\n", cursor->user_data);
	}

	/* Iterate over the list and remove elements from it */
	SS_LIST_FOR_EACH_SAVE(&list, cursor, precursor, struct list_test, list) {
		printf(" user_data=%d\n", cursor->user_data);

		/* Remove element from the list, this must not disturb the
		 * list iteration */
		ss_list_remove(&cursor->list);
		cursor = NULL;
	}

	/* Prove that the list is emty, we should see no output */
	SS_LIST_FOR_EACH(&list, cursor, struct list_test, list) {
		printf(" user_data=%d (this shouldn't be here!)\n",
		       cursor->user_data);
	}
}

int main(int argc, char **argv)
{
	add_iterate_and_remove_test();
	return 0;
}
