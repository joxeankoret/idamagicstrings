#-------------------------------------------------------------------------------
#
# IDAPython script to show many features extracted from debugging strings. It's
# also able to rename functions based on the guessed function name & rename
# functions based on the source code file they belong to.
#
# Copyright (c) 2018, Joxean Koret
# Licensed under the GNU GPL v3.
#
#-------------------------------------------------------------------------------

from __future__ import print_function

import os
import re

from collections import Counter

import idaapi
import idautils

from idautils import Strings
from idaapi import PluginForm, Choose2
from PyQt5 import QtCore, QtGui, QtWidgets

try:
  import nltk
  from nltk.tokenize import word_tokenize
  from nltk.tag import pos_tag

  has_nltk = True
except ImportError:
  has_nltk = False

try:
  long        # Python 2
except NameError:
  long = int  # Python 3

#-------------------------------------------------------------------------------
PROGRAM_NAME = "IDAMagicStrings"

#-------------------------------------------------------------------------------
SOURCE_FILES_REGEXP = r"([a-z_\/\\][a-z0-9_/\\:\-\.@]+\.(c|cc|cxx|c\+\+|cpp|h|hpp|m|rs|go|ml))($|:| )"

LANGS = {}
LANGS["C/C++"] = ["c", "cc", "cxx", "cpp", "h", "hpp"]
LANGS["C"] = ["c"]
LANGS["C++"] = ["cc", "cxx", "cpp", "hpp", "c++"]
LANGS["Obj-C"] = ["m"]
LANGS["Rust"] = ["rs"]
LANGS["Golang"] = ["go"]
LANGS["OCaml"] = ["ml"]

#-------------------------------------------------------------------------------
FUNCTION_NAMES_REGEXP = r"([a-z_][a-z0-9_]+((::)+[a-z_][a-z0-9_]+)*)"
NOT_FUNCTION_NAMES = ["copyright", "char", "bool", "int", "unsigned", "long",
  "double", "float", "signed", "license", "version", "cannot", "error",
  "invalid", "null", "warning", "general", "argument", "written", "report",
  "failed", "assert", "object", "integer", "unknown", "localhost", "native",
  "memory", "system", "write", "read", "open", "close", "help", "exit", "test",
  "return", "libs", "home", "ambiguous", "internal", "request", "inserting",
  "deleting", "removing", "updating", "adding", "assertion", "flags",
  "overflow", "enabled", "disabled", "enable", "disable", "virtual", "client",
  "server", "switch", "while", "offset", "abort", "panic", "static", "updated",
  "pointer", "reason", "month", "year", "week", "hour", "minute", "second", 
  'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
  'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
  'september', 'october', 'november', 'december', "arguments", "corrupt", 
  "corrupted", "default", "success", "expecting", "missing", "phrase", 
  "unrecognized", "undefined",
  ]

#-------------------------------------------------------------------------------
FOUND_TOKENS = {}
TOKEN_TYPES = ["NN", "NNS", "NNP", "JJ", "VB", "VBD", "VBG", "VBN", "VBP", "VBZ"]
def nltk_preprocess(strings):
  if not has_nltk:
    return

  strings = "\n".join(map(str, list(strings)))
  tokens = re.findall(FUNCTION_NAMES_REGEXP, strings)
  l = []
  for token in tokens:
    l.append(token[0])
  word_tags = nltk.pos_tag(l)
  for word, tag in word_tags:
    try:
      FOUND_TOKENS[word.lower()].add(tag)
    except:
      FOUND_TOKENS[word.lower()] = set([tag])

#-------------------------------------------------------------------------------
def get_source_strings(min_len = 4, strtypes = [0, 1]):
  strings = Strings()
  strings.setup(strtypes = strtypes)

  src_langs = Counter()
  total_files = 0
  d = {}
  for s in strings:
    if s and s.length > min_len:
      ret = re.findall(SOURCE_FILES_REGEXP, str(s), re.IGNORECASE)
      if ret and len(ret) > 0:
        refs = list(DataRefsTo(s.ea))
        if len(refs) > 0:
          total_files += 1
          full_path    = ret[0][0]
          d[full_path] = []
          _, file_ext  = os.path.splitext(full_path.lower())
          file_ext = file_ext.strip(".")
          for key in LANGS:
            if file_ext in LANGS[key]:
              src_langs[key] += 1

          for ref in refs:
            d[full_path].append([ref, GetFunctionName(ref), str(s)])

  nltk_preprocess(strings)
  if len(d) > 0:
    print("Programming languages found:\n")
    for key in src_langs:
      print("  %s %f%%" % (key.ljust(10), src_langs[key] * 100. / total_files))
    print("\n")

  return d, strings

#-------------------------------------------------------------------------------
def handler(item, column_no):
  ea = item.ea
  if isEnabled(ea):
    jumpto(ea)

#-------------------------------------------------------------------------------
class CBaseTreeViewer(PluginForm):
  def populate_tree(self, d):
    # Clear previous items
    self.tree.clear()

    # Build the tree
    for key in d:
      src_file_item = QtWidgets.QTreeWidgetItem(self.tree)
      src_file_item.setText(0, key)
      src_file_item.ea = BADADDR

      for ea, name, str_data in d[key]:
        item = QtWidgets.QTreeWidgetItem(src_file_item)
        item.setText(0, "%s [0x%08x] %s" % (name, ea, str_data))
        item.ea = ea

    self.tree.itemDoubleClicked.connect(handler)

  def OnCreate(self, form):
    # Get parent widget
    self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

    # Create tree control
    self.tree = QtWidgets.QTreeWidget()
    self.tree.setHeaderLabels(("Names",))
    self.tree.setColumnWidth(0, 100)

    if self.d is None:
      self.d, self.s = get_source_strings()
    d = self.d

    # Create layout
    layout = QtWidgets.QVBoxLayout()
    layout.addWidget(self.tree)
    self.populate_tree(d)

    # Populate PluginForm
    self.parent.setLayout(layout)

  def Show(self, title, d = None):
    self.d = d
    return PluginForm.Show(self, title, options = PluginForm.FORM_PERSIST)

#-------------------------------------------------------------------------------
def basename(path):
  pos1 = path[::-1].find("\\")
  pos2 = path[::-1].find("/")

  if pos1 == -1: pos1 = len(path)
  if pos2 == -1: pos2 = len(path)
  pos = min(pos1, pos2)

  return path[len(path)-pos:]

#-------------------------------------------------------------------------------
class CSourceFilesChooser(Choose2):
  def __init__(self, title):
    columns = [ ["Line", 4], ["Full path", 20], ["Filename", 15], ["EA", 16], ["Function Name", 18], ["String data", 40], ]
    Choose2.__init__(self, title, columns, Choose2.CH_MULTI)
    self.n = 0
    self.icon = -1
    self.selcount = 0
    self.modal = False
    self.items = []
    self.selected_items = []

    d, s = get_source_strings()
    keys = d.keys()
    keys.sort()
    
    i = 0
    for key in keys:
      for ea, name, str_data in d[key]:
        line = ["%03d" % i, key, basename(key), "0x%08x" % ea, name, str_data]
        self.items.append(line)
        i += 1

    self.d = d
    self.s = s

  def show(self):
    ret = self.Show(False)
    if ret < 0:
      return False

    self.cmd_all          = self.AddCommand("Rename all to filename_EA")
    self.cmd_all_sub      = self.AddCommand("Rename all sub_* to filename_EA")
    self.cmd_selected     = self.AddCommand("Rename selected to filename_EA")
    self.cmd_selected_sub = self.AddCommand("Rename selected sub_* to filename_EA")
    return self.d

  def OnCommand(self, n, cmd_id):
    # Aditional right-click-menu commands handles
    if cmd_id == self.cmd_all:
      l = range(len(self.items))
    elif cmd_id == self.cmd_all_sub:
      l = []
      for i, item in enumerate(self.items):
        if item[4].startswith("sub_"):
          l.append(i)
    elif cmd_id == self.cmd_selected:
      l = list(self.selected_items)
    elif cmd_id == self.cmd_selected_sub:
      l = []
      for i, item in enumerate(self.items):
        if item[4].startswith("sub_"):
          if i in self.selected_items:
            l.append(i)

    self.rename_items(l)

  def rename_items(self, items):
    for i in items:
      item = self.items[i]
      ea = long(item[3], 16)
      candidate, _ = os.path.splitext(item[2])
      name = "%s_%08x" % (candidate, ea)
      func = idaapi.get_func(ea)
      if func is not None:
        ea = func.startEA
        MakeName(ea, name)
      else:
        line = "WARNING: Cannot rename 0x%08x to %s because there is no function associated."
        print(line % (ea, name))

  def OnGetLine(self, n):
    return self.items[n]

  def OnGetSize(self):
    n = len(self.items)
    return n

  def OnDeleteLine(self, n):
    del self.items[n]
    return n

  def OnRefresh(self, n):
    return n

  def OnSelectLine(self, n):
    self.selcount += 1
    row = self.items[n]
    ea = long(row[3], 16)
    if isEnabled(ea):
      jumpto(ea)

  def OnSelectionChange(self, sel_list):
    self.selected_items = sel_list

#-------------------------------------------------------------------------------
class CCandidateFunctionNames(Choose2):
  def __init__(self, title, l):
    columns = [ ["Line", 4], ["EA", 16], ["Function Name", 25], ["Candidate", 25], ["FP?", 2], ["Strings", 50], ]
    Choose2.__init__(self, title, columns, Choose2.CH_MULTI)
    self.n = 0
    self.icon = -1
    self.selcount = 0
    self.modal = False
    self.items = []
    self.selected_items = []

    i = 0
    for item in l:
      bin_func  = item[1]
      candidate = item[2]
      seems_false = str(int(self.looks_false(bin_func, candidate)))
      line = ["%03d" % i, "0x%08x" % item[0], item[1], item[2], seems_false, ", ".join(item[3]) ]
      self.items.append(line)
      i += 1

    self.items = sorted(self.items, key=lambda x: x[4])

  def show(self):
    ret = self.Show(False)
    if ret < 0:
      return False

    self.cmd_rename_all      = self.AddCommand("Rename all functions")
    self.cmd_rename_sub      = self.AddCommand("Rename all sub_* functions")
    self.cmd_rename_selected = self.AddCommand("Rename selected function(s)")
    self.cmd_rename_sub_sel  = self.AddCommand("Rename selected sub_* function(s)")

  def OnCommand(self, n, cmd_id):
    # Aditional right-click-menu commands handles
    if cmd_id == self.cmd_rename_all:
      l = range(len(self.items))
    elif cmd_id == self.cmd_rename_selected:
      l = list(self.selected_items)
    elif cmd_id == self.cmd_rename_sub:
      l = []
      for i, item in enumerate(self.items):
        if item[2].startswith("sub_"):
          l.append(i)
    elif cmd_id == self.cmd_rename_sub_sel:
      l = []
      for i, item in enumerate(self.items):
        if item[2].startswith("sub_"):
          if i in self.selected_items:
            l.append(i)
    else:
      raise Exception("Unknown menu command!")

    self.rename_items(l)

  def rename_items(self, items):
    for i in items:
      item = self.items[i]
      ea = long(item[1], 16)
      candidate = item[3]
      MakeName(ea, candidate)

  def OnGetLine(self, n):
    return self.items[n]

  def OnGetSize(self):
    n = len(self.items)
    return n

  def OnDeleteLine(self, n):
    del self.items[n]
    return n

  def OnRefresh(self, n):
    return n

  def OnSelectLine(self, n):
    self.selcount += 1
    row = self.items[n]
    ea = long(row[1], 16)
    if isEnabled(ea):
      jumpto(ea)

  def OnSelectionChange(self, sel_list):
    self.selected_items = sel_list

  def looks_false(self, bin_func, candidate):
    if not bin_func.startswith("sub_"):
      if bin_func.find(candidate) == -1 and candidate.find(bin_func) == -1:
        return True
    return False

  def OnGetLineAttr(self, n):
    item = self.items[n]
    bin_func  = item[2]
    candidate = item[3]
    if self.looks_false(bin_func, candidate):
      return [0x026AFD, 0]
    return [0xFFFFFF, 0]

#-------------------------------------------------------------------------------
def show_tree(d = None):
  tree_frm = CBaseTreeViewer()
  tree_frm.Show(PROGRAM_NAME + ": Source code tree", d)

#-------------------------------------------------------------------------------
def seems_function_name(candidate):
  if len(candidate) >= 6 and candidate.lower() not in NOT_FUNCTION_NAMES:
    if candidate.upper() != candidate:
      return True
  return False

#-------------------------------------------------------------------------------
def show_function_names(strings_list):
  rarity = {}
  func_names = {}
  raw_func_strings = {}
  for s in strings_list:
    ret = re.findall(FUNCTION_NAMES_REGEXP, str(s), re.IGNORECASE)
    if len(ret) > 0:
      candidate = ret[0][0]
      if seems_function_name(candidate):
        ea = s.ea
        refs = DataRefsTo(ea)
        found = False
        for ref in refs:
          func = idaapi.get_func(ref)
          if func is not None:
            found = True
            key = func.startEA

            if has_nltk:
              if candidate not in FOUND_TOKENS:
                continue
              
              found = False
              for tkn_type in TOKEN_TYPES:
                if tkn_type in FOUND_TOKENS[candidate]:
                  found = True
                  break

              if not found:
                continue

            try:
              rarity[candidate].add(key)
            except KeyError:
              rarity[candidate] = set([key])

            try:
              func_names[key].add(candidate)
            except KeyError:
              func_names[key] = set([candidate])

            try:
              raw_func_strings[key].add(str(s))
            except:
              raw_func_strings[key] = set([str(s)])

  final_list = []
  for key in func_names:
    candidates = set()
    for candidate in func_names[key]:
      if len(rarity[candidate]) == 1:
        candidates.add(candidate)

    if len(candidates) == 1:
      raw_strings = list(raw_func_strings[key])
      raw_strings = map(repr, raw_strings)
      
      func_name = GetFunctionName(key)
      tmp = Demangle(func_name, INF_SHORT_DN)
      if tmp is not None:
        func_name = tmp
      final_list.append([key, func_name, list(candidates)[0], raw_strings])

  cfn = CCandidateFunctionNames(PROGRAM_NAME + ": Candidate Function Names", final_list)
  cfn.show()

#-------------------------------------------------------------------------------
def main():
  ch = CSourceFilesChooser(PROGRAM_NAME + ": Source code files")
  ch.show()
  d = ch.d
  show_tree(d)
  show_function_names(ch.s)

if __name__ == "__main__":
  main()
