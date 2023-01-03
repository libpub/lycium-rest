#!/usr/bin/env python
# -*- coding: utf-8 -*-

import i18n

def format_items_as_tree(items: list, pk: str, belongs_to_key: str, locale_params: dict, contains_none: bool = False):
    # items_map = {row.get(pk, 0): row for row in items}
    tree_items = []
    if contains_none:
        tree_items.append({pk: 0, 'label': i18n.t('basic.none', **locale_params)})
    formed_items = {}
    # prepare elements into formed belongs to array
    for row in items:
        ele: dict = row.copy()
        id = row.get(pk, 0)
        belongs_to_id = row.get(belongs_to_key, 0)
        if belongs_to_id:
            if belongs_to_id in formed_items:
                formed_items[belongs_to_id].append(ele)
            else:
                formed_items[belongs_to_id] = [ele]
        else:
            tree_items.append(ele)
    
    for ele in tree_items:
        deep_fill_tree_item_children(ele, formed_items, pk)
    return tree_items
    
def deep_fill_tree_item_children(item: dict, formed_items: dict, pk: str):
    id = item.get(pk, 0)
    if not id:
        return
    if id in formed_items:
        item['children'] = formed_items[id]
        for ele in item['children']:
            deep_fill_tree_item_children(ele, formed_items, pk)
        
