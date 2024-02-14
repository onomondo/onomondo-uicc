/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stddef.h>
#include <stdbool.h>

/*! List element of a double linked list */
struct ss_list {
	/*! reference to the previous element */
	struct ss_list *previous;
	/*! referenc to the next element */
	struct ss_list *next;
};

/*! Initialize list (pre and nxt point to themselves).
 *  \param[out] list pointer to the begin of the list. */
static inline void ss_list_init(struct ss_list *list)
{
	list->previous = list;
	list->next = list->previous;
}

/*! Check if list properly initialized (next/previous pointer are not NULL).
 *  \param[in] list pointer to the begin of the list.
 *  \returns true when initialized, false otherwise. */
static inline bool ss_list_initialized(const struct ss_list *list)
{
	return list->next != NULL && list->previous != NULL;
}

/*! Put an element on the end of the list.
 *  \param[inout] list pointer to the begin of the list.
 *  \param[inout] elem pointer to the list member of the element to add. */
static inline void ss_list_put(struct ss_list *list, struct ss_list *elem)
{
	struct ss_list *old_list_end = list->previous;

	/* Connect element to the end of the list */
	list->previous = elem;
	elem->next = list;

	/* Connect old end to the new element */
	old_list_end->next = elem;
	elem->previous = old_list_end;
}

/*! Push an element on the beginning of the list.
 *  \param[inout] list pointer to the begin of the list.
 *  \param[inout] elem pointer to the list member of the element to add. */
static inline void ss_list_push(struct ss_list *list, struct ss_list *elem)
{
	struct ss_list *old_list_begin = list->next;

	/* Connect element to the beginning of the list */
	list->next = elem;
	elem->previous = list;

	/* Connect old beginning to the new element */
	old_list_begin->previous = elem;
	elem->next = old_list_begin;
}

/*! Get the next struct for the next list element (helper macro for SS_LIST_FOR_EACH).
 *  \param[in] list pointer to the begin of the list.
 *  \param[in] struct_type type description of the element struct.
 *  \param[in] struct_member name of the list begin member inside the element struct.
 *  \returns pointer to list element. */
#define SS_LIST_GET_NEXT(list, struct_type, struct_member) (void*)((list)->next - offsetof(struct_type, struct_member))

/*! Get the struct for the current list element (helper macro for SS_LIST_FOR_EACH).
 *  \param[in] list pointer to the begin of the list.
 *  \param[in] struct_type type description of the element struct.
 *  \param[in] struct_member name of the list begin member inside the element struct.
 *  \returns pointer to list element. */
#define SS_LIST_GET(list, struct_type, struct_member) (void*)(list - offsetof(struct_type, struct_member))

/* iterate over all structs managed by the list */
#define SS_LIST_FOR_EACH(list_begin, struct_cursor, struct_type, struct_member) \
	for (struct_cursor = SS_LIST_GET_NEXT(list_begin, struct_type, struct_member); \
	     struct_cursor != SS_LIST_GET(list_begin, struct_type, struct_member); \
	     struct_cursor = SS_LIST_GET_NEXT(&(struct_cursor)->struct_member, struct_type, struct_member))

/* iterate over all structs managed by the list, but keep a precursor in case
 * the cursor gets freed during the iteration. */
#define SS_LIST_FOR_EACH_SAVE(list_begin, struct_cursor, struct_precursor, struct_type, struct_member) \
	for (struct_cursor = SS_LIST_GET_NEXT(list_begin, struct_type, struct_member), \
	     struct_precursor = SS_LIST_GET_NEXT((list_begin)->next, struct_type, struct_member); \
	     struct_cursor != SS_LIST_GET(list_begin, struct_type, struct_member); \
	     struct_cursor = struct_precursor, \
	     struct_precursor = SS_LIST_GET_NEXT(&(struct_precursor)->struct_member, struct_type, struct_member))

/*! Remove an element from the list by unlinking it from the list.
 *  \param[inout] elem pointer to the list member of the element to remove. */
static inline void ss_list_remove(struct ss_list *elem)
{
	struct ss_list *next_elem = elem->next;
	struct ss_list *previous_elem = elem->previous;

	next_elem->previous = previous_elem;
	previous_elem->next = next_elem;

	elem->next = NULL;
	elem->previous = NULL;
}

/*! Check whether the list is empty or not.
 *  \param[in] list pointer to the begin of the list.
 *  \returns true when the list is empty, false otherwise. */
static inline bool ss_list_empty(const struct ss_list *list)
{
	return list->next == list;
}
