#!/usr/bin/env python

# Import stuff I need to use
import sys
import argparse
import re
import os.path

try:
    import xmltodict
except ImportError:
    print 'xmltodict required. Install using `pip install xmltodict`'


class StigBenchmark(object):
    """
    STIG Benchmark class
    """
    # Initialize new benchmark object
    def __init__(self, xccdf, benchtype):
        with open(xccdf) as outf:
            self.xccdf = xmltodict.parse(outf.read())
        self.benchtype = benchtype

    def sev_to_cat(self, sev):
        switcher = {
            'high': 'cat1',
            'medium': 'cat2',
            'low': 'cat3',
        }
        return switcher.get(sev)

    def dump(self, path):
        for sev in ['cat1', 'cat2', 'cat3']:
            outfile = os.path.join(path, sev + '.yml')
            with open(outfile, 'w') as outf:
                outf.write('')

        for group in self.xccdf['Benchmark']['Group']:
            rule_id = group['Rule']['@id']
            rule_sev = group['Rule']['@severity']
            rule_sev_group = self.sev_to_cat(rule_sev)
            rule_title = group['Rule']['title'].replace('"', '\'')
            stig_id = group['Rule']['version']
            outfile = os.path.join(path, rule_sev_group + '.yml')

            with open(outfile, 'a') as outf:
                outf.write('- name: "{} | {} | {}"\n'.format(rule_sev.upper(),
                                                          stig_id,
                                                          rule_title))
                outf.write('  block:\n')
                for check in ['AUDIT', 'PATCH']:
                    self.write_rule(rule_id, stig_id, rule_sev, rule_title,
                                    check, outf)
                outf.write('  tags:\n')
                outf.write('      - {}\n'.format(self.sev_to_cat(rule_sev)))
                outf.write('      - {}\n'.format(rule_sev))
                outf.write('      - {}\n'.format(stig_id))
                outf.write('      - notimplemented\n')
                outf.write('\n')

    def write_rule(self, rule_id, stig_id, rule_sev, rule_title,
                   check_type, outf):
        outf.write('    - name: "{} | {} | {} | {}"\n'.format(rule_sev.upper(),
                                                          stig_id,
                                                          check_type.upper(),
                                                          rule_title))
        outf.write('      command: "true"\n')
        if check_type.upper() == 'AUDIT':
            outf.write('      register: result\n')
            outf.write('      changed_when: no\n')
            outf.write('      check_mode: no\n')
        outf.write('      with_items:\n')
        outf.write('          - not implemented\n')
        outf.write('      tags:\n')
        outf.write('          - {}\n'.format(check_type.lower()))


class CisBenchmark(object):
    """
    CIS Benchmark class
    """
    # Initialize new benchmark object
    def __init__(self, xccdf, benchtype):
        with open(xccdf) as outf:
            self.xccdf = xmltodict.parse(outf.read())
        self.benchtype = benchtype
        self.level1rules, self.level2rules = self.parse_profiles()
        self.sections = []
        for sect in self.xccdf['Benchmark']['Group']:
            self.sections.append(self.flatten_groups(sect))

    def parse_profiles(self):
        level1rules = []
        level2rules = []
        for rule in self.xccdf['Benchmark']['Profile'][0]['select']:
            level1rules.append(rule['@idref'])

        for rule in self.xccdf['Benchmark']['Profile'][1]['select']:
            level2rules.append(rule['@idref'])

        return level1rules, level2rules

    def flatten_groups(self, groups):
        rules = []
        try:
            if isinstance(groups['Group'], (list)):
                for group in groups['Group']:
                    rules.extend(self.flatten_groups(group))
            elif isinstance(groups['Group'], (dict)):
                rules.extend(self.flatten_groups(groups['Group']))
        except KeyError:
            pass
        try:
            if isinstance(groups['Rule'], (list)):
                for rule in groups['Rule']:
                    rules.append(rule)
            elif isinstance(groups['Rule'], (dict)):
                rules.append(groups['Rule'])
        except KeyError:
            pass
        return rules

    def dump(self, path):
        sect_num = 1
        rule_num_re = re.compile('xccdf_org\.cisecurity\.benchmarks_rule_([\d\.]+)_.*')

        for sect in self.sections:
            outfile = os.path.join(path, 'section' + str(sect_num) + '.yml')
            with open(outfile, 'w') as outf:
                for rule in sect:
                    rule_id = rule['@id']
                    rule_num = rule_num_re.search(rule_id).group(1)
                    rule_title = rule['title']['#text'].replace('"', '\'')
                    rule_sev = 'NOTSCORED'
                    if rule['@role'] == 'full':
                        rule_sev = 'SCORED'
                    for check in ['AUDIT', 'PATCH']:
                        self.write_rule(rule_id, rule_num, rule_sev,
                                        rule_title, check, outf)

            sect_num += 1

    def write_rule(self, rule_id, rule_num, rule_sev, rule_title, check_type,
                   outf):
        outf.write('- name: "{} | {} | {} | {}"\n'.format(rule_sev, rule_num,
                                                          check_type.upper(),
                                                          rule_title))
        outf.write('  command: true\n')
        if check_type.upper() == 'AUDIT':
            outf.write('  register: result\n')
            outf.write('  always_run: yes\n')
            outf.write('  changed_when: no\n')
            outf.write('  ignore_errors: yes\n')
        outf.write('  tags:\n')
        if rule_id in self.level1rules:
            outf.write('      - level1\n')
        outf.write('      - level2\n')
        outf.write('      - {}\n'.format(check_type.lower()))
        outf.write('      - rule_{}\n'.format(rule_num))
        outf.write('\n')


def valid(outdir):
    if not os.path.exists(outdir):
        raise argparse.ArgumentTypeError("%s not a valid directory" % outdir)
    return outdir


def main(args):
    if args.benchmark_type == 'CIS':
        benchmark = CisBenchmark(args.xccdf_file, args.benchmark_type)
    elif args.benchmark_type == 'STIG':
        benchmark = StigBenchmark(args.xccdf_file, args.benchmark_type)
    benchmark.dump(args.output_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse security benchmarks'
                                     ' from multiple sources (CIS, STIG, etc)'
                                     ' in xccdf format and output starter'
                                     ' files for use with Ansible roles.')

    parser.add_argument('-X', '--xccdf', dest='xccdf_file',
                        help='Path to xccdf benchmark file to parse')

    parser.add_argument('-P', '--output-path', required=False,
                        dest='output_path',
                        help='Default `cwd` Path to dump Ansible YAML files',
                        type=valid, default=os.getcwd())

    parser.add_argument('-T', '--benchmark-type', required=False,
                        dest='benchmark_type', default='CIS',
                        help='Default CIS. The benchmark type.')

    args = parser.parse_args()
    main(args)
    sys.exit(0)
