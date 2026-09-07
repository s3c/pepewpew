import argparse


def build_parser():
    parser = argparse.ArgumentParser(description='Command line tool to fiddle with PE file properties')
    parser.add_argument('-if', '--input-file', help='Full path of input file', metavar='filename', required=True)
    parser.add_argument('-of', '--output-file', help='Full path of output file', metavar='filename', required=True)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('-pe', '--proxy-exports', help='Full path of file to proxy exports to', metavar='filename')
    actions.add_argument('-rm', '--remove-mangling', help='Remove mangling gcc adds to x86 files using STDAPI',
                         action='store_true')
    actions.add_argument('-rt', '--remove-tls', help='Remove TLS directory', action='store_true')
    actions.add_argument('-is', '--import-shuffle',
                         help='Shuffle the order IMAGE_IMPORT_DESCRIPTOR entries appear in within the file',
                         action='store_true')
    actions.add_argument('-ps', '--patch-start', nargs=2,
                         help='Patch the entry point to point to param 1 marker, insert data read from param 2 file at that point, and add a '
                              'relative jump back to the original entry point')
    actions.add_argument('-ac', '--append-certificate', help='Patch the binary with a fake certificate',
                         metavar='filename')
    actions.add_argument('-fz', '--fix-zero', help='Fix sections with zero raw size', action='store_true')
    actions.add_argument('-rs', '--rename-section', nargs=2, help='Rename a section', metavar=('section', 'new_name'))
    actions.add_argument('-ed', '--exe-to-dll', help='Convert a EXE to an DLL', action='store_true')
    return parser


def write_output(path, output_binary):
    with open(path, 'wb') as output_file:
        output_file.write(output_binary)


def main(argv=None):
    args = build_parser().parse_args(argv)

    from .core import (
        CustomExportDirectory,
        append_certificate,
        exe_to_dll,
        fix_zero_section_size,
        import_shuffle,
        patch_start,
        remove_tls,
        rename_section,
    )

    with open(args.input_file, 'rb') as input_file:
        input_binary = input_file.read()

    if args.proxy_exports:
        with open(args.proxy_exports, 'rb') as forward_file:
            forward_binary = forward_file.read()
        export_directory = CustomExportDirectory(forward_binary, forward_path=args.proxy_exports)
        output_binary = export_directory.apply(input_binary)
    elif args.remove_mangling:
        export_directory = CustomExportDirectory(input_binary)
        output_binary = export_directory.apply(input_binary, unmangle=True)
    elif args.import_shuffle:
        output_binary = import_shuffle(input_binary)
    elif args.patch_start:
        with open(args.patch_start[1], 'rb') as patch_file:
            patch_data = patch_file.read()
        output_binary = patch_start(input_binary, args.patch_start[0], patch_data)
    elif args.append_certificate:
        with open(args.append_certificate, 'rb') as certificate_file:
            input_certificate = certificate_file.read()
        output_binary = append_certificate(input_binary, input_certificate)
    elif args.remove_tls:
        output_binary = remove_tls(input_binary)
    elif args.fix_zero:
        output_binary = fix_zero_section_size(input_binary)
    elif args.rename_section:
        output_binary = rename_section(input_binary, args.rename_section[0], args.rename_section[1])
    elif args.exe_to_dll:
        output_binary = exe_to_dll(input_binary)

    write_output(args.output_file, output_binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
