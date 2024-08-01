"use strict";

(function()
{
    /** @const */
    var ON_LOCALHOST = !location.hostname.endsWith("copy.sh");

    /**
     * @return {Object.<string, string>}
     */
    function get_query_arguments()
    {
        var query = location.search.substr(1).split("&");
        var parameters = {};

        for(var i = 0; i < query.length; i++)
        {
            var param = query[i].split("=");
            parameters[param[0]] = decodeURIComponent(param.slice(1).join("="));
        }

        return parameters;
    }

    function set_title(text)
    {
        document.title = text + " - Virtual x86" +  (DEBUG ? " - debug" : "");
        const description = document.querySelector("meta[name=description]");
        description && (description.content = "Running " + text);
    }

    function format_timestamp(time)
    {
        if(time < 60)
        {
            return time + "s";
        }
        else if(time < 3600)
        {
            return (time / 60 | 0) + "m " + v86util.pad0(time % 60, 2) + "s";
        }
        else
        {
            return (time / 3600 | 0) + "h " +
                v86util.pad0((time / 60 | 0) % 60, 2) + "m " +
                v86util.pad0(time % 60, 2) + "s";
        }
    }

    var progress_ticks = 0;

    function show_progress(e)
    {
        var el = $("loading");
        el.style.display = "block";

        if(e.file_name.endsWith(".wasm"))
        {
            const parts = e.file_name.split("/");
            el.textContent = "Fetching " + parts[parts.length - 1] + " ...";
            return;
        }

        if(e.file_index === e.file_count - 1 && e.loaded >= e.total - 2048)
        {
            // last file is (almost) loaded
            el.textContent = "Done downloading. Starting now ...";
            return;
        }

        var line = "Downloading images ";

        if(typeof e.file_index === "number" && e.file_count)
        {
            line += "[" + (e.file_index + 1) + "/" + e.file_count + "] ";
        }

        if(e.total && typeof e.loaded === "number")
        {
            var per100 = Math.floor(e.loaded / e.total * 100);
            per100 = Math.min(100, Math.max(0, per100));

            var per50 = Math.floor(per100 / 2);

            line += per100 + "% [";
            line += "#".repeat(per50);
            line += " ".repeat(50 - per50) + "]";
        }
        else
        {
            line += ".".repeat(progress_ticks++ % 50);
        }

        el.textContent = line;
    }

    function $(id)
    {
        return document.getElementById(id);
    }

    // these values are stored in localStorage
    const elements_to_restore = [
        "memory_size",
        "video_memory_size",
        "networking_proxy",
        "disable_audio",
        "enable_acpi",
        "boot_order",
    ];

    function onload()
    {
        if(!window.WebAssembly)
        {
            alert("Your browser is not supported because it doesn't support WebAssembly");
            return;
        }

        var settings = {};

        $("start_emulation").onclick = function()
        {
            // Save entered options into the local storage
            for(const id of elements_to_restore)
            {
                const element = $(id);
                if(element)
                {
                    if(element.tagName === "SELECT" || element.type !== "checkbox")
                    {
                        window.localStorage.setItem(id, element.value);
                    }
                    else
                    {
                        window.localStorage.setItem(id, element.checked);
                    }
                }
            }

            $("boot_options").style.display = "none";
            set_profile("custom");

            var images = [];
            var last_file;

            var floppy_file = $("floppy_image").files[0];
            if(floppy_file)
            {
                last_file = floppy_file;
                settings.fda = { buffer: floppy_file };
            }

            var cd_file = $("cd_image").files[0];
            if(cd_file)
            {
                last_file = cd_file;
                settings.cdrom = { buffer: cd_file };
            }

            var hda_file = $("hda_image").files[0];
            if(hda_file)
            {
                last_file = hda_file;
                settings.hda = { buffer: hda_file };
            }

            var hdb_file = $("hdb_image") && $("hdb_image").files[0];
            if(hdb_file)
            {
                last_file = hdb_file;
                settings.hdb = { buffer: hdb_file };
            }

            if($("multiboot_image"))
            {
                var multiboot_file = $("multiboot_image").files[0];
                if(multiboot_file)
                {
                    last_file = multiboot_file;
                    settings.multiboot = { buffer: multiboot_file };
                }
            }

            if(last_file)
            {
                set_title(last_file.name);
            }

            start_emulation(settings);
        };

        if(DEBUG)
        {
            debug_onload();
        }

        const query_args = get_query_arguments();
        const host = query_args["cdn"] || (ON_LOCALHOST ? "images/" : "//i.copy.sh/");

        // Abandonware OS images are from https://winworldpc.com/library/operating-systems
        var oses = [
            {
                id: "archlinux",
                name: "Arch Linux",
                memory_size: 512 * 1024 * 1024,
                vga_memory_size: 8 * 1024 * 1024,
                state: { url: host + "arch_state.bin.zst" },
                filesystem: {
                    baseurl: host + "arch/",
                },
            },
            {
                id: "archlinux-boot",
                name: "Arch Linux",
                memory_size: 512 * 1024 * 1024,
                vga_memory_size: 8 * 1024 * 1024,
                filesystem: {
                    baseurl: host + "arch/",
                    basefs: { url: host + "fs.json" },
                },
                cmdline: [
                    "rw apm=off vga=0x344 video=vesafb:ypan,vremap:8",
                    "root=host9p rootfstype=9p rootflags=trans=virtio,cache=loose",
                    "mitigations=off audit=0",
                    "init_on_free=on",
                    "tsc=reliable",
                    "random.trust_cpu=on",
                    "nowatchdog",
                    "init=/usr/bin/init-openrc net.ifnames=0 biosdevname=0",
                ].join(" "),
                bzimage_initrd_from_filesystem: true,
            },
            {
                id: "copy/skiffos",
                name: "SkiffOS",
                cdrom: {
                    url: host + "skiffos/.iso",
                    size: 124672000,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                memory_size: 512 * 1024 * 1024,
            },
            {
                id: "serenity",
                name: "SerenityOS",
                hda: {
                    url: host + "serenity-v3/.img.zst",
                    size: 734003200,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                memory_size: 512 * 1024 * 1024,
                state: { url: host + "serenity_state-v4.bin.zst" },
                homepage: "https://serenityos.org/",
                mac_address_translation: true,
            },
            {
                id: "serenity-boot",
                name: "SerenityOS",
                hda: {
                    url: host + "serenity-v3/.img.zst",
                    size: 734003200,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                memory_size: 512 * 1024 * 1024,
                homepage: "https://serenityos.org/",
            },
            {
                id: "redox",
                name: "Redox",
                hda: {
                    url: host + "redox_demo_i686_2022-11-26_643_harddrive/.img",
                    size: 512 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                memory_size: 512 * 1024 * 1024,
                state: { url: host + "redox_state.bin.zst" },
                homepage: "https://www.redox-os.org/",
                acpi: true,
            },
            {
                id: "redox-boot",
                name: "Redox",
                hda: {
                    url: host + "redox_demo_i686_2022-11-26_643_harddrive/.img",
                    size: 512 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                memory_size: 512 * 1024 * 1024,
                homepage: "https://www.redox-os.org/",
                acpi: true,
            },
            {
                id: "helenos",
                memory_size: 256 * 1024 * 1024,
                cdrom: {
                    url: host + "HelenOS-0.11.2-ia32.iso",
                    size: 25765888,
                    async: false,
                },
                name: "HelenOS",
                homepage: "http://www.helenos.org/",
            },
            {
                id: "fiwix",
                memory_size: 256 * 1024 * 1024,
                hda: {
                    url: host + "FiwixOS-3.3-i386/.img",
                    size: 1024 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                name: "FiwixOS",
                homepage: "https://www.fiwix.org/",
            },
            {
                id: "haiku",
                memory_size: 512 * 1024 * 1024,
                hda: {
                    url: host + "haiku-v3/.img",
                    size: 1 * 1024 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                state: { url: host + "haiku_state-v3.bin.zst" },
                name: "Haiku",
                homepage: "https://www.haiku-os.org/",
            },
            {
                id: "haiku-boot",
                memory_size: 512 * 1024 * 1024,
                hda: {
                    url: host + "haiku-v3/.img",
                    size: 1 * 1024 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                name: "Haiku",
                homepage: "https://www.haiku-os.org/",
            },
            {
                id: "msdos",
                hda: {
                    url: host + "msdos.img",
                    size: 8 * 1024 * 1024,
                    async: false,
                },
                name: "MS-DOS",
            },
            {
                id: "freedos",
                fda: {
                    url: host + "freedos722.img",
                    size: 737280,
                    async: false,
                },
                name: "FreeDOS",
            },
            {
                id: "freegem",
                hda: {
                    url: host + "freegem/.bin",
                    size: 209715200,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Freedos with FreeGEM",
            },
            {
                id: "psychdos",
                hda: {
                    url: host + "psychdos/.img",
                    size: 549453824,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "PsychDOS",
                homepage: "https://psychoslinux.gitlab.io/DOS/INDEX.HTM",
            },
            {
                id: "oberon",
                hda: {
                    url: host + "oberon.img",
                    size: 24 * 1024 * 1024,
                    async: false,
                },
                name: "Oberon",
            },
            {
                id: "windows1",
                fda: {
                    url: host + "windows101.img",
                    size: 1474560,
                    async: false,
                },
                name: "Windows",
            },
            {
                id: "linux26",
                cdrom: {
                    url: host + "linux.iso",
                    size: 6547456,
                    async: false,
                },
                name: "Linux",
            },
            {
                id: "linux3",
                cdrom: {
                    url: host + "linux3.iso",
                    size: 8638464,
                    async: false,
                },
                name: "Linux",
            },
            {
                id: "linux4",
                cdrom: {
                    url: host + "linux4.iso",
                    size: 7731200,
                    async: false,
                },
                name: "Linux",
                filesystem: {},
            },
            {
                id: "buildroot",
                bzimage: {
                    url: host + "buildroot-bzimage.bin",
                    size: 5166352,
                    async: false,
                },
                name: "Buildroot Linux",
                filesystem: {},
                cmdline: "tsc=reliable mitigations=off random.trust_cpu=on",
            },
            {
                id: "basiclinux",
                hda: {
                    url: host + "bl3-5.img",
                    size: 104857600,
                    async: false,
                },
                name: "BasicLinux",
            },
            {
                id: "xpud",
                cdrom: {
                    url: host + "xpud-0.9.2.iso",
                    size: 67108864,
                    async: false,
                },
                name: "xPUD",
                memory_size: 256 * 1024 * 1024,
            },
            {
                id: "elks",
                hda: {
                    url: host + "elks-hd32-fat.img",
                    size: 32514048,
                    async: false,
                },
                name: "ELKS",
            },
            {
                id: "nodeos",
                bzimage: {
                    url: host + "nodeos-kernel.bin",
                    size: 14452000,
                    async: false,
                },
                name: "NodeOS",
                cmdline: "tsc=reliable mitigations=off random.trust_cpu=on",
            },
            {
                id: "dsl",
                memory_size: 256 * 1024 * 1024,
                cdrom: {
                    url: host + "dsl-4.11.rc2.iso",
                    size: 52824064,
                    async: false,
                },
                name: "Damn Small Linux",
                homepage: "http://www.damnsmalllinux.org/",
            },
            {
                id: "xwoaf",
                memory_size: 256 * 1024 * 1024,
                cdrom: {
                    url: host + "xwoaf_rebuild4.iso",
                    size: 2205696,
                    async: false,
                },
                name: "xwoaf",
                homepage: "https://pupngo.dk/xwinflpy/xwoaf_rebuild.html",
            },
            {
                id: "minix",
                name: "Minix",
                memory_size: 256 * 1024 * 1024,
                cdrom: {
                    url: host + "minix-3.3.0/.iso",
                    size: 605581312,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                homepage: "https://www.minix3.org/",
            },
            {
                id: "kolibrios",
                fda: {
                    url: ON_LOCALHOST ?
                            host + "kolibri.img" :
                            "//builds.kolibrios.org/en_US/data/data/kolibri.img",
                    size: 1474560,
                    async: false,
                },
                name: "KolibriOS",
                homepage: "https://kolibrios.org/en/",
            },
            {
                id: "kolibrios-fallback",
                fda: {
                    url: host + "kolibri.img",
                    size: 1474560,
                    async: false,
                },
                name: "KolibriOS",
            },
            {
                id: "mu",
                hda: {
                    url: host + "mu-shell.img",
                    size: 10321920,
                    async: false,
                },
                memory_size: 256 * 1024 * 1024,
                name: "Mu",
                homepage: "https://github.com/akkartik/mu",
            },
            {
                id: "openbsd",
                hda: {
                    url: host + "openbsd/.img",
                    size: 1073741824,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                state: { url: host + "openbsd_state.bin.zst" },
                memory_size: 256 * 1024 * 1024,
                name: "OpenBSD",
            },
            {
                id: "sortix",
                cdrom: {
                    url: host + "sortix-1.0-i686.iso",
                    size: 71075840,
                    async: false,
                },
                memory_size: 512 * 1024 * 1024,
                name: "Sortix",
            },
            {
                id: "openbsd-boot",
                hda: {
                    url: host + "openbsd/.img",
                    size: 1073741824,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                memory_size: 256 * 1024 * 1024,
                name: "OpenBSD",
                //acpi: true, // doesn't seem to work
            },
            {
                id: "netbsd",
                hda: {
                    url: host + "netbsd/.img",
                    size: 511000064,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                memory_size: 256 * 1024 * 1024,
                name: "NetBSD",
            },
            {
                id: "crazierl",
                multiboot: {
                    url: host + "crazierl-elf.img",
                    size: 896592,
                    async: false,
                },
                initrd: {
                    url: host + "crazierl-initrd.img",
                    size: 18448316,
                    async: false,
                },
                acpi: true,
                cmdline: "kernel /libexec/ld-elf32.so.1",
                memory_size: 128 * 1024 * 1024,
                name: "Crazierl",
            },
            {
                id: "solos",
                fda: {
                    url: host + "os8.img",
                    async: false,
                    size: 1474560,
                },
                name: "Sol OS",
                homepage: "http://oby.ro/os/",
            },
            {
                id: "bootchess",
                fda: {
                    url: host + "bootchess.img",
                    async: false,
                    size: 1474560,
                },
                name: "BootChess",
                homepage: "http://www.pouet.net/prod.php?which=64962",
            },
            {
                id: "bootbasic",
                fda: {
                    url: host + "bootbasic.img",
                    async: false,
                    size: 1474560,
                },
                name: "bootBASIC",
                homepage: "https://github.com/nanochess/bootBASIC",
            },
            {
                id: "sectorlisp",
                fda: {
                    url: host + "sectorlisp-friendly.bin",
                    async: false,
                    size: 512,
                },
                name: "SectorLISP",
                homepage: "https://justine.lol/sectorlisp2/",
            },
            {
                id: "sectorforth",
                fda: {
                    url: host + "sectorforth.img",
                    async: false,
                    size: 512,
                },
                name: "sectorforth",
                homepage: "https://github.com/cesarblum/sectorforth",
            },
            {
                id: "floppybird",
                fda: {
                    url: host + "floppybird.img",
                    async: false,
                    size: 1474560,
                },
                name: "Floppy Bird",
                homepage: "http://mihail.co/floppybird",
            },
            {
                id: "stillalive",
                fda: {
                    url: host + "stillalive-os.img",
                    async: false,
                    size: 368640,
                },
                name: "Still Alive",
                homepage: "https://github.com/maniekx86/stillalive-os",
            },
            {
                id: "hello-v86",
                fda: {
                    url: host + "hello-v86.img",
                    async: false,
                    size: 512,
                },
                name: "Hello v86",
            },
            {
                id: "duskos",
                hda: {
                    url: host + "duskos.img",
                    async: false,
                    size: 8388608,
                },
                name: "Dusk OS",
                homepage: "http://duskos.org/",
            },
            {
                id: "windows2000",
                memory_size: 512 * 1024 * 1024,
                hda: {
                    url: host + "windows2k/.img",
                    size: 2 * 1024 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Windows 2000",
                state: { url: host + "windows2k_state-v2.bin.zst" },
                mac_address_translation: true,
            },
            {
                id: "windows2000-boot",
                memory_size: 512 * 1024 * 1024,
                hda: {
                    url: host + "windows2k/.img",
                    size: 2 * 1024 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Windows 2000",
            },
            {
                id: "windowsnt4",
                memory_size: 512 * 1024 * 1024,
                hda: {
                    url: host + "winnt4_noacpi/.img",
                    size: 523837440,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Windows NT 4.0",
                cpuid_level: 2,
            },
            {
                id: "windowsnt3",
                memory_size: 256 * 1024 * 1024,
                hda: {
                    url: host + "winnt31/.img",
                    size: 87 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Windows NT 3.1",
            },
            {
                id: "windows98",
                memory_size: 128 * 1024 * 1024,
                hda: {
                    url: host + "windows98/.img",
                    size: 300 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Windows 98",
                state: { url: host + "windows98_state.bin.zst" },
                mac_address_translation: true,
            },
            {
                id: "windows98-boot",
                memory_size: 128 * 1024 * 1024,
                hda: {
                    url: host + "windows98/.img",
                    size: 300 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Windows 98",
            },
            {
                id: "windows95",
                memory_size: 32 * 1024 * 1024,
                hda: {
                    url: host + "w95/.img",
                    size: 242049024,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Windows 95",
                state: { url: host + "windows95_state.bin.zst" },
            },
            {
                id: "windows95-boot",
                memory_size: 32 * 1024 * 1024,
                hda: {
                    url: host + "w95/.img",
                    size: 242049024,
                    async: true,
                    fixed_chunk_size: 256 * 1024,
                    use_parts: true,
                },
                name: "Windows 95",
            },
            {
                id: "windows30",
                memory_size: 64 * 1024 * 1024,
                cdrom: {
                    url: host + "Win30.iso",
                    size: 7774208,
                    async: false,
                },
                name: "Windows 3.0",
            },
            {
                id: "windows31",
                memory_size: 64 * 1024 * 1024,
                hda: {
                    url: host + "win31.img",
                    async: false,
                    size: 34463744,
                },
                name: "Windows 3.1",
            },
            {
                id: "tilck",
                memory_size: 128 * 1024 * 1024,
                hda: {
                    url: host + "tilck.img",
                    async: false,
                    size: 37748736,
                },
                name: "Tilck",
                homepage: "https://github.com/vvaltchev/tilck",
            },
            {
                id: "sanos",
                memory_size: 128 * 1024 * 1024,
                hda: {
                    url: host + "sanos-flp.img",
                    async: false,
                    size: 1474560,
                },
                name: "sanos",
                homepage: "http://www.jbox.dk/sanos/",
            },
            {
                id: "freebsd",
                memory_size: 256 * 1024 * 1024,
                hda: {
                    url: host + "freebsd/.img",
                    size: 2147483648,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                state: { url: host + "freebsd_state.bin.zst" },
                name: "FreeBSD",
            },
            {
                id: "freebsd-boot",
                memory_size: 256 * 1024 * 1024,
                hda: {
                    url: host + "freebsd/.img",
                    size: 2147483648,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                name: "FreeBSD",
            },
            {
                id: "reactos",
                memory_size: 512 * 1024 * 1024,
                hda: {
                    url: host + "reactos/.img",
                    size: 500 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                state: { url: host + "reactos_state.bin.zst" },
                mac_address_translation: true,
                name: "ReactOS",
                homepage: "https://reactos.org/",
            },
            {
                id: "reactos-boot",
                memory_size: 512 * 1024 * 1024,
                hda: {
                    url: host + "reactos/.img",
                    size: 500 * 1024 * 1024,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                name: "ReactOS",
                homepage: "https://reactos.org/",
            },
            {
                id: "skift",
                cdrom: {
                    url: host + "skift-20200910.iso",
                    size: 64452608,
                    async: false,
                },
                name: "Skift",
                homepage: "https://skiftos.org/",
            },
            {
                id: "snowdrop",
                fda: {
                    url: host + "snowdrop.img",
                    size: 1440 * 1024,
                    async: false,
                },
                name: "Snowdrop",
                homepage: "http://www.sebastianmihai.com/snowdrop/",
            },
            {
                id: "openwrt",
                hda: {
                    url: host + "openwrt-18.06.1-x86-legacy-combined-squashfs.img",
                    size: 19846474,
                    async: false,
                },
                name: "OpenWrt",
            },
            {
                id: "qnx",
                fda: {
                    url: host + "qnx-demo-network-4.05.img",
                    size: 1474560,
                    async: false
                },
                name: "QNX 4.05",
            },
            {
                id: "9front",
                memory_size: 128 * 1024 * 1024,
                hda: {
                    url: host + "9front-8963.f84cf1e60427675514fb056cc1723e45da01e043.386/.iso",
                    size: 477452288,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                state: { url: host + "9front_state-v2.bin.zst" },
                acpi: true,
                name: "9front",
                homepage: "https://9front.org/",
            },
            {
                id: "9front-boot",
                memory_size: 128 * 1024 * 1024,
                hda: {
                    url: host + "9front-8963.f84cf1e60427675514fb056cc1723e45da01e043.386/.iso",
                    size: 477452288,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                acpi: true,
                name: "9front",
                homepage: "https://9front.org/",
            },
            {
                id: "mobius",
                fda: {
                    url: host + "mobius-fd-release5.img",
                    size: 1474560,
                    async: false,
                },
                name: "Mobius",
            },
            {
                id: "android",
                memory_size: 512 * 1024 * 1024,
                cdrom: {
                    url: host + "android-x86-1.6-r2/.iso",
                    size: 54661120,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                name: "Android",
            },
            {
                id: "android4",
                memory_size: 512 * 1024 * 1024,
                cdrom: {
                    url: host + "android_x86_nonsse3_4.4r1_20140904/.iso",
                    size: 247463936,
                    async: true,
                    fixed_chunk_size: 1024 * 1024,
                    use_parts: true,
                },
                name: "Android",
            },
            {
                id: "tinycore",
                memory_size: 256 * 1024 * 1024,
                hda: {
                    url: host + "TinyCore-11.0.iso",
                    size: 19922944,
                    async: false,
                },
                name: "Tinycore",
                homepage: "http://www.tinycorelinux.net/",
            },
            {
                id: "freenos",
                memory_size: 256 * 1024 * 1024,
                cdrom: {
                    url: host + "FreeNOS-1.0.3.iso",
                    async: false,
                    size: 11014144,
                },
                name: "FreeNOS",
                acpi: true,
                homepage: "http://www.freenos.org/",
            },
            {
                id: "syllable",
                memory_size: 512 * 1024 * 1024,
                hda: {
                    url: host + "syllable-destop-0.6.7/.img",
                    async: true,
                    size: 500 * 1024 * 1024,
                    fixed_chunk_size: 512 * 1024,
                    use_parts: true,
                },
                name: "Syllable",
                homepage: "http://syllable.metaproject.frl/",
            },
            {
                id: "toaruos",
                memory_size: 512 * 1024 * 1024,
                cdrom: {
                    url: host + "toaruos-1.6.1-core.iso",
                    size: 67567616,
                    async: false,
                },
                name: "ToaruOS",
                acpi: true,
                homepage: "https://toaruos.org/",
            },
            {
                id: "nopeos",
                cdrom: {
                    url: host + "nopeos-0.1.iso",
                    size: 532480,
                    async: false,
                },
                name: "Nope OS",
                homepage: "https://github.com/d99kris/nopeos",
            },
            {
                id: "soso",
                cdrom: {
                    url: host + "soso.iso",
                    size: 22546432,
                    async: false,
                },
                name: "Soso",
                homepage: "https://github.com/ozkl/soso",
            },
            {
                id: "pcmos",
                fda: {
                    url: host + "PCMOS386-9-user-patched.img",
                    size: 1440 * 1024,
                    async: false,
                },
                name: "PC-MOS/386",
                homepage: "https://github.com/roelandjansen/pcmos386v501",
            },
            {
                id: "jx",
                fda: {
                    url: host + "jx-demo.img",
                    size: 1440 * 1024,
                    async: false,
                },
                name: "JX",
                homepage: "https://www4.cs.fau.de/Projects/JX/index.html",
            },
            {
                id: "house",
                fda: {
                    url: host + "hOp-0.8.img",
                    size: 1440 * 1024,
                    async: false,
                },
                name: "House",
                homepage: "https://programatica.cs.pdx.edu/House/",
            },
            {
                id: "bleskos",
                name: "BleskOS",
                cdrom: {
                    url: host + "bleskos_2024u32.iso",
                    size: 1835008,
                    async: false,
                },
                homepage: "https://github.com/VendelinSlezak/BleskOS",
            },
            {
                id: "boneos",
                name: "BoneOS",
                cdrom: {
                    url: host + "BoneOS.iso",
                    size: 11429888,
                    async: false,
                },
                homepage: "https://amanuel.io/projects/BoneOS/",
            },
            {
                id: "mikeos",
                name: "MikeOS",
                cdrom: {
                    url: host + "mikeos.iso",
                    size: 11429888,
                    async: false,
                },
                homepage: "https://mikeos.sourceforge.net/",
            },
        ];

        if(DEBUG)
        {
            // see tests/kvm-unit-tests/x86/
            var tests = [
                "realmode",
                // All tests below require an APIC
                "cmpxchg8b",
                "port80",
                "setjmp",
                "sieve",
                "hypercall", // crashes
                "init", // stops execution
                "msr", // TODO: Expects 64 bit msrs
                "smap", // test stops, SMAP not enabled
                "tsc_adjust", // TODO: IA32_TSC_ADJUST
                "tsc", // TODO: rdtscp
                "rmap_chain", // crashes
                "memory", // missing mfence (uninteresting)
                "taskswitch", // TODO: Jump
                "taskswitch2", // TODO: Call TSS
                "eventinj", // Missing #nt
                "ioapic",
                "apic",
            ];

            for(const test of tests)
            {
                oses.push({
                    name: "Test case: " + test,
                    id: "test-" + test,
                    memory_size: 128 * 1024 * 1024,
                    multiboot: { url: "tests/kvm-unit-tests/x86/" + test + ".flat" }
                });
            }
        }

        var profile = query_args["profile"];

        if(!profile && !DEBUG)
        {
            const link = document.createElement("link");
            link.rel = "prefetch";
            link.href = "build/v86.wasm";
            document.head.appendChild(link);
        }

        const link = document.createElement("link");
        link.rel = "prefetch";
        link.href = "build/xterm.js";
        document.head.appendChild(link);

        if(query_args["disable_jit"])
        {
            settings.disable_jit = true;
        }

        if(query_args["use_bochs_bios"])
        {
            settings.use_bochs_bios = true;
        }

        const m = parseInt(query_args["m"], 10);
        if(m > 0)
        {
            settings.memory_size = Math.max(16, m) * 1024 * 1024;
        }

        const vram = parseInt(query_args["vram"], 10);
        if(vram > 0)
        {
            settings.vga_memory_size = vram * 1024 * 1024;
        }

        settings.networking_proxy = query_args["networking_proxy"];
        settings.audio = query_args["audio"] !== "0";
        settings.acpi = query_args["acpi"];

        for(var i = 0; i < oses.length; i++)
        {
            var infos = oses[i];

            if(profile === infos.id)
            {
                start_profile(infos);
                return;
            }

            var element = $("start_" + infos.id);

            if(element)
            {
                element.onclick = function(infos, element, e)
                {
                    e.preventDefault();
                    set_profile(infos.id);
                    element.blur();

                    start_profile(infos);
                }.bind(this, infos, element);
            }
        }

        if(profile === "custom")
        {
            if(query_args["hda.url"])
            {
                settings.hda = {
                    size: parseInt(query_args["hda.size"], 10) || undefined,
                    url: query_args["hda.url"],
                    async: true,
                };
            }

            if(query_args["cdrom.url"])
            {
                settings.cdrom = {
                    size: parseInt(query_args["cdrom.size"], 10) || undefined,
                    url: query_args["cdrom.url"],
                    async: true,
                };
            }

            if(query_args["fda.url"])
            {
                settings.fda = {
                    size: parseInt(query_args["fda.size"], 10) || undefined,
                    url: query_args["fda.url"],
                    async: false,
                };
            }

            if(settings.fda || settings.cdrom || settings.hda)
            {
                $("boot_options").style.display = "none";

                start_emulation(settings, done);
                return;
            }
        }
        else if(/^[a-zA-Z0-9\-_]+\/[a-zA-Z0-9\-_]+$/g.test(profile))
        {
            // experimental: server that allows user-uploaded images

            const base = "https://v86-user-images.b-cdn.net/" + profile;

            fetch(base + "/profile.json")
                .catch(e => alert("Profile not found: " + profile))
                .then(response => response.json())
                .then(p => {
                    function handle_image(o)
                    {
                        return o && { url: base + "/" + o["url"], async: o["async"], size: o["size"] };
                    }

                    start_profile({
                        id: p["id"],
                        name: p["name"],
                        memory_size: p["memory_size"],
                        vga_memory_size: p["vga_memory_size"],
                        acpi: p["acpi"],
                        boot_order: p["boot_order"],
                        hda: handle_image(p["hda"]),
                        cdrom: handle_image(p["cdrom"]),
                        fda: handle_image(p["fda"]),
                        multiboot: handle_image(p["multiboot"]),
                        bzimage: handle_image(p["bzimage"]),
                        initrd: handle_image(p["initrd"]),
                    });
                });

            return;
        }

        for(const id of elements_to_restore)
        {
            const saved_value = window.localStorage.getItem(id);

            if(saved_value)
            {
                const element = $(id);
                if(element)
                {
                    if(element.type === "checkbox")
                    {
                        element.checked = saved_value === "true" ? true : false;
                    }
                    else
                    {
                        element.value = saved_value;
                    }
                }
            }
        }

        function start_profile(infos)
        {
            $("boot_options").style.display = "none";
            set_title(infos.name);

            settings.filesystem = infos.filesystem;

            if(infos.state)
            {
                $("reset").style.display = "none";
                settings.initial_state = infos.state;
            }

            settings.fda = infos.fda;
            settings.cdrom = infos.cdrom;
            settings.hda = infos.hda;
            settings.multiboot = infos.multiboot;
            settings.bzimage = infos.bzimage;
            settings.initrd = infos.initrd;
            settings.cmdline = infos.cmdline;
            settings.bzimage_initrd_from_filesystem = infos.bzimage_initrd_from_filesystem;
            settings.mac_address_translation = infos.mac_address_translation;
            settings.cpuid_level = infos.cpuid_level;

            settings.acpi = (!infos.state && settings.acpi !== undefined) ? settings.acpi : infos.acpi;
            settings.memory_size = (!infos.state && settings.memory_size) ? settings.memory_size : infos.memory_size;
            settings.vga_memory_size = (!infos.state && settings.vga_memory_size) ? settings.vga_memory_size : infos.vga_memory_size;

            settings.disable_vga_display = infos.disable_vga_display;

            settings.id = infos.id;

            if(infos.boot_order !== undefined)
            {
                settings.boot_order = infos.boot_order;
            }

            let chunk_size = parseInt(query_args["chunk_size"], 10);
            if(chunk_size >= 0)
            {
                if(chunk_size)
                {
                    chunk_size = Math.min(4 * 1024 * 1024, Math.max(512, chunk_size));
                    chunk_size = 1 << Math.ceil(Math.log2(chunk_size));
                }
                else
                {
                    chunk_size = undefined;
                }

                if(settings.hda)
                {
                    settings.hda.fixed_chunk_size = chunk_size;
                }

                if(settings.cdrom)
                {
                    settings.cdrom.fixed_chunk_size = chunk_size;
                }
            }

            if(!DEBUG && infos.homepage)
            {
                $("description").style.display = "block";
                const link = document.createElement("a");
                link.href = infos.homepage;
                link.textContent = infos.name;
                link.target = "_blank";
                $("description").appendChild(document.createTextNode("Running "));
                $("description").appendChild(link);
            }

            start_emulation(settings, done);
        }

        function done(emulator)
        {
            if(query_args["c"])
            {
                setTimeout(function()
                {
                    //emulator.serial0_send(query_args["c"] + "\n");
                    emulator.keyboard_send_text(query_args["c"] + "\n");
                }, 25);
            }
        }
    }

    function debug_onload()
    {
        // called on window.onload, in debug mode

        var log_levels = $("log_levels");

        if(log_levels)
        {
            for(var i = 0; i < LOG_NAMES.length; i++)
            {
                var mask = LOG_NAMES[i][0];

                if(mask === 1)
                    continue;

                var name = LOG_NAMES[i][1].toLowerCase(),
                    input = document.createElement("input"),
                    label = document.createElement("label");

                input.type = "checkbox";

                label.htmlFor = input.id = "log_" + name;

                if(LOG_LEVEL & mask)
                {
                    input.checked = true;
                }
                input.mask = mask;

                label.appendChild(input);
                label.appendChild(document.createTextNode(v86util.pads(name, 4) + " "));
                log_levels.appendChild(label);

                if(i === Math.floor(LOG_NAMES.length / 2))
                {
                    log_levels.appendChild(document.createTextNode("\n"));
                }
            }

            log_levels.onchange = function(e)
            {
                var target = e.target,
                    mask = target.mask;

                if(target.checked)
                {
                    LOG_LEVEL |= mask;
                }
                else
                {
                    LOG_LEVEL &= ~mask;
                }

                target.blur();
            };
        }
    }

    window.addEventListener("load", onload, false);

    // old webkit fires popstate on every load, fuck webkit
    // https://code.google.com/p/chromium/issues/detail?id=63040
    window.addEventListener("load", function()
    {
        setTimeout(function()
        {
            window.addEventListener("popstate", onpopstate);
        }, 0);
    });

    // works in firefox and chromium
    if(document.readyState === "complete")
    {
        onload();
    }

    /** @param {?=} done */
    function start_emulation(settings, done)
    {
        /** @const */
        var MB = 1024 * 1024;

        var memory_size = settings.memory_size;

        if(!memory_size)
        {
            memory_size = parseInt($("memory_size").value, 10) * MB;

            if(!memory_size)
            {
                alert("Invalid memory size - reset to 128MB");
                memory_size = 128 * MB;
            }
        }

        var vga_memory_size = settings.vga_memory_size;

        if(!vga_memory_size)
        {
            vga_memory_size = parseInt($("video_memory_size").value, 10) * MB;

            if(!vga_memory_size)
            {
                alert("Invalid video memory size - reset to 8MB");
                vga_memory_size = 8 * MB;
            }
        }

        if(!settings.fda)
        {
            var floppy_file = $("floppy_image").files[0];
            if(floppy_file)
            {
                settings.fda = { buffer: floppy_file };
            }
        }

        if(!settings.bzimage)
        {
            var bzimage = $("bzimage").files[0];
            if(bzimage)
            {
                settings.bzimage = { buffer: bzimage };
            }
        }

        if(!settings.initrd)
        {
            var initrd = $("initrd").files[0];
            if(initrd)
            {
                settings.initrd = { buffer: initrd };
            }
        }

        const networking_proxy = settings.networking_proxy === undefined ? $("networking_proxy").value : settings.networking_proxy;
        const disable_audio = $("disable_audio").checked || !settings.audio;
        const enable_acpi = !settings.initial_state && settings.acpi === undefined ? $("enable_acpi").checked : settings.acpi;

        /** @const */
        var BIOSPATH = "bios/";

        if(settings.use_bochs_bios)
        {
            var biosfile = "bochs-bios.bin";
            var vgabiosfile = "bochs-vgabios.bin";
        }
        else
        {
            var biosfile = DEBUG ? "seabios-debug.bin" : "seabios.bin";
            var vgabiosfile = DEBUG ? "vgabios-debug.bin" : "vgabios.bin";
        }

        var bios;
        var vga_bios;

        // a bios is only needed if the machine is booted
        if(!settings.initial_state)
        {
            bios = {
                url: BIOSPATH + biosfile,
            };
            vga_bios = {
                url: BIOSPATH + vgabiosfile,
            };
        }

        var emulator = new V86({
            memory_size: memory_size,
            vga_memory_size: vga_memory_size,

            screen_container: settings.disable_vga_display ? null : $("screen_container"),

            boot_order: settings.boot_order || parseInt($("boot_order").value, 16) || 0,

            network_relay_url: ON_LOCALHOST ? "ws://localhost:8080/" : networking_proxy,

            bios: bios,
            vga_bios: vga_bios,

            fda: settings.fda,
            hda: settings.hda,
            hdb: settings.hdb,
            cdrom: settings.cdrom,

            multiboot: settings.multiboot,
            bzimage: settings.bzimage,
            initrd: settings.initrd,
            cmdline: settings.cmdline,
            bzimage_initrd_from_filesystem: settings.bzimage_initrd_from_filesystem,

            acpi: enable_acpi,
            disable_jit: settings.disable_jit,
            initial_state: settings.initial_state,
            filesystem: settings.filesystem || {},
            disable_speaker: disable_audio,
            mac_address_translation: settings.mac_address_translation,
            cpuid_level: settings.cpuid_level,

            autostart: true,
        });

        if(DEBUG) window["emulator"] = emulator;

        emulator.add_listener("emulator-ready", function()
        {
            if(DEBUG)
            {
                debug_start(emulator);
            }

            if(emulator.v86.cpu.wm.exports["profiler_is_enabled"]())
            {
                const CLEAR_STATS = false;

                var panel = document.createElement("pre");
                document.body.appendChild(panel);

                setInterval(function()
                    {
                        if(!emulator.is_running())
                        {
                            return;
                        }

                        const text = print_stats.stats_to_string(emulator.v86.cpu);
                        panel.textContent = text;

                        CLEAR_STATS && emulator.v86.cpu.clear_opstats();
                    }, CLEAR_STATS ? 5000 : 1000);
            }

            if(settings.id === "dsl" || settings.id === "helenos" || settings.id === "android" || settings.id === "android4")
            {
                setTimeout(() => {
                    // hack: Start automatically
                    emulator.keyboard_send_text("\n");
                }, 3000);
            }

            init_ui(settings, emulator);

            done && done(emulator);
        });

        emulator.add_listener("download-progress", function(e)
        {
            show_progress(e);
        });

        emulator.add_listener("download-error", function(e)
        {
            var el = $("loading");
            el.style.display = "block";
            el.textContent = "Loading " + e.file_name + " failed. Check your connection " +
                             "and reload the page to try again.";
        });
    }

    /**
     * @param {Object} settings
     * @param {V86} emulator
     */
    function init_ui(settings, emulator)
    {
        $("boot_options").style.display = "none";
        $("loading").style.display = "none";
        $("runtime_options").style.display = "block";
        $("runtime_infos").style.display = "block";
        if(!settings.disable_vga_display) $("screen_container").style.display = "block";

        if(settings.filesystem)
        {
            init_filesystem_panel(emulator);
        }
        else
        {
            emulator.add_listener("9p-attach", function()
            {
                init_filesystem_panel(emulator);
            });
        }

        $("run").onclick = function()
        {
            if(emulator.is_running())
            {
                $("run").value = "Run";
                emulator.stop();
            }
            else
            {
                $("run").value = "Pause";
                emulator.run();
            }

            $("run").blur();
        };

        $("exit").onclick = function()
        {
            emulator.stop();
            location.href = location.pathname;
        };

        $("lock_mouse").onclick = function()
        {
            if(!mouse_is_enabled)
            {
                $("toggle_mouse").onclick();
            }

            emulator.lock_mouse();
            $("lock_mouse").blur();
        };

        var mouse_is_enabled = true;

        $("toggle_mouse").onclick = function()
        {
            mouse_is_enabled = !mouse_is_enabled;

            emulator.mouse_set_status(mouse_is_enabled);
            $("toggle_mouse").value = (mouse_is_enabled ? "Dis" : "En") + "able mouse";
            $("toggle_mouse").blur();
        };


        var last_tick = 0;
        var running_time = 0;
        var last_instr_counter = 0;
        var interval = null;
        var os_uses_mouse = false;
        var total_instructions = 0;

        function update_info()
        {
            var now = Date.now();

            var instruction_counter = emulator.get_instruction_counter();

            if(instruction_counter < last_instr_counter)
            {
                // 32-bit wrap-around
                last_instr_counter -= 0x100000000;
            }

            var last_ips = instruction_counter - last_instr_counter;
            last_instr_counter = instruction_counter;
            total_instructions += last_ips;

            var delta_time = now - last_tick;

            if(delta_time)
            {
                running_time += delta_time;
                last_tick = now;

                $("speed").textContent = (last_ips / 1000 / delta_time).toFixed(1);
                $("avg_speed").textContent = (total_instructions / 1000 / running_time).toFixed(1);
                $("running_time").textContent = format_timestamp(running_time / 1000 | 0);
            }
        }

        emulator.add_listener("emulator-started", function()
        {
            last_tick = Date.now();
            interval = setInterval(update_info, 1000);
        });

        emulator.add_listener("emulator-stopped", function()
        {
            update_info();
            if(interval !== null)
            {
                clearInterval(interval);
            }
        });

        var stats_9p = {
            read: 0,
            write: 0,
            files: [],
        };

        emulator.add_listener("9p-read-start", function(args)
        {
            const file = args[0];
            stats_9p.files.push(file);
            $("info_filesystem").style.display = "block";
            $("info_filesystem_status").textContent = "Loading ...";
            $("info_filesystem_last_file").textContent = file;
        });
        emulator.add_listener("9p-read-end", function(args)
        {
            stats_9p.read += args[1];
            $("info_filesystem_bytes_read").textContent = stats_9p.read;

            const file = args[0];
            stats_9p.files = stats_9p.files.filter(f => f !== file);

            if(stats_9p.files[0])
            {
                $("info_filesystem_last_file").textContent = stats_9p.files[0];
            }
            else
            {
                $("info_filesystem_status").textContent = "Idle";
            }
        });
        emulator.add_listener("9p-write-end", function(args)
        {
            stats_9p.write += args[1];
            $("info_filesystem_bytes_written").textContent = stats_9p.write;

            if(!stats_9p.files[0])
            {
                $("info_filesystem_last_file").textContent = args[0];
            }
        });

        var stats_storage = {
            read: 0,
            read_sectors: 0,
            write: 0,
            write_sectors: 0,
        };

        $("ide_type").textContent = emulator.disk_images.cdrom ? " (CD-ROM)" : " (hard disk)";

        emulator.add_listener("ide-read-start", function()
        {
            $("info_storage").style.display = "block";
            $("info_storage_status").textContent = "Loading ...";
        });
        emulator.add_listener("ide-read-end", function(args)
        {
            stats_storage.read += args[1];
            stats_storage.read_sectors += args[2];

            $("info_storage_status").textContent = "Idle";
            $("info_storage_bytes_read").textContent = stats_storage.read;
            $("info_storage_sectors_read").textContent = stats_storage.read_sectors;
        });
        emulator.add_listener("ide-write-end", function(args)
        {
            stats_storage.write += args[1];
            stats_storage.write_sectors += args[2];

            $("info_storage_bytes_written").textContent = stats_storage.write;
            $("info_storage_sectors_written").textContent = stats_storage.write_sectors;
        });

        var stats_net = {
            bytes_transmitted: 0,
            bytes_received: 0,
        };

        emulator.add_listener("eth-receive-end", function(args)
        {
            stats_net.bytes_received += args[0];

            $("info_network").style.display = "block";
            $("info_network_bytes_received").textContent = stats_net.bytes_received;
        });
        emulator.add_listener("eth-transmit-end", function(args)
        {
            stats_net.bytes_transmitted += args[0];

            $("info_network").style.display = "block";
            $("info_network_bytes_transmitted").textContent = stats_net.bytes_transmitted;
        });


        emulator.add_listener("mouse-enable", function(is_enabled)
        {
            os_uses_mouse = is_enabled;
            $("info_mouse_enabled").textContent = is_enabled ? "Yes" : "No";
        });

        emulator.add_listener("screen-set-mode", function(is_graphical)
        {
            if(is_graphical)
            {
                $("info_vga_mode").textContent = "Graphical";
            }
            else
            {
                $("info_vga_mode").textContent = "Text";
                $("info_res").textContent = "-";
                $("info_bpp").textContent = "-";
            }
        });
        emulator.add_listener("screen-set-size-graphical", function(args)
        {
            $("info_res").textContent = args[0] + "x" + args[1];
            $("info_bpp").textContent = args[4];
        });


        $("reset").onclick = function()
        {
            emulator.restart();
            $("reset").blur();
        };

        add_image_download_button(settings.hda, emulator.disk_images.hda, "hda");
        add_image_download_button(settings.hdb, emulator.disk_images.hdb, "hdb");
        add_image_download_button(settings.fda, emulator.disk_images.fda, "fda");
        add_image_download_button(settings.fdb, emulator.disk_images.fdb, "fdb");
        add_image_download_button(settings.cdrom, emulator.disk_images.cdrom, "cdrom");

        function add_image_download_button(obj, buffer, type)
        {
            var elem = $("get_" + type + "_image");

            if(!obj || obj.size > 100 * 1024 * 1024)
            {
                elem.style.display = "none";
                return;
            }

            elem.onclick = function(e)
            {
                const filename = buffer.file && buffer.file.name || (settings.id + (type === "cdrom" ? ".iso" : ".img"));

                if(buffer.get_as_file)
                {
                    var file = buffer.get_as_file(filename);
                    download(file, filename);
                }
                else
                {
                    buffer.get_buffer(function(b)
                    {
                        if(b)
                        {
                            dump_file(b, filename);
                        }
                        else
                        {
                            alert("The file could not be loaded. Maybe it's too big?");
                        }
                    });
                }

                elem.blur();
            };
        }

        $("change_fda_image").value = settings.fda ? "Eject floppy image" : "Insert floppy image";
        $("change_fda_image").onclick = function()
        {
            if(emulator.v86.cpu.devices.fdc.fda_image)
            {
                emulator.eject_fda();
                $("change_fda_image").value = "Insert floppy image";
            }
            else
            {
                const file_input = document.createElement("input");
                file_input.type = "file";
                file_input.onchange = async function(e)
                {
                    const file = file_input.files[0];
                    if(file)
                    {
                        await emulator.set_fda({ buffer: file });
                        $("change_fda_image").value = "Eject floppy image";
                    }
                };
                file_input.click();
            }
            $("change_fda_image").blur();
        };

        $("memory_dump").onclick = function()
        {
            const mem8 = emulator.v86.cpu.mem8;
            dump_file(new Uint8Array(mem8.buffer, mem8.byteOffset, mem8.length), "v86memory.bin");
            $("memory_dump").blur();
        };

        //$("memory_dump_dmp").onclick = function()
        //{
        //    var memory = emulator.v86.cpu.mem8;
        //    var memory_size = memory.length;
        //    var page_size = 4096;
        //    var header = new Uint8Array(4096);
        //    var header32 = new Int32Array(header.buffer);

        //    header32[0] = 0x45474150; // 'PAGE'
        //    header32[1] = 0x504D5544; // 'DUMP'

        //    header32[0x10 >> 2] = emulator.v86.cpu.cr[3]; // DirectoryTableBase
        //    header32[0x24 >> 2] = 1; // NumberProcessors
        //    header32[0xf88 >> 2] = 1; // DumpType: full dump
        //    header32[0xfa0 >> 2] = header.length + memory_size; // RequiredDumpSpace

        //    header32[0x064 + 0 >> 2] = 1; // NumberOfRuns
        //    header32[0x064 + 4 >> 2] = memory_size / page_size; // NumberOfPages
        //    header32[0x064 + 8 >> 2] = 0; // BasePage
        //    header32[0x064 + 12 >> 2] = memory_size / page_size; // PageCount

        //    dump_file([header, memory], "v86memory.dmp");

        //    $("memory_dump_dmp").blur();
        //};

        $("capture_network_traffic").onclick = function()
        {
            this.value = "0 packets";

            let capture = [];

            function do_capture(direction, data)
            {
                capture.push({ direction, time: performance.now() / 1000, hex_dump: hex_dump(data) });
                $("capture_network_traffic").value = capture.length + " packets";
            }

            emulator.emulator_bus.register("net0-receive", do_capture.bind(this, "I"));
            emulator.add_listener("net0-send", do_capture.bind(this, "O"));

            this.onclick = function()
            {
                const capture_raw = capture.map(({ direction, time, hex_dump }) => {
                    // https://www.wireshark.org/docs/wsug_html_chunked/ChIOImportSection.html
                    // In wireshark: file -> import from hex -> tick direction indication, timestamp %s.%f
                    return direction + " " + time.toFixed(6) + hex_dump + "\n";
                }).join("");
                dump_file(capture_raw, "traffic.hex");
                capture = [];
                this.value = "0 packets";
            };
        };


        $("save_state").onclick = async function()
        {
            const result = await emulator.save_state();
            dump_file(result, "v86state.bin");

            $("save_state").blur();
        };

        $("load_state").onclick = function()
        {
            $("load_state_input").click();
            $("load_state").blur();
        };

        $("load_state_input").onchange = async function()
        {
            var file = this.files[0];

            if(!file)
            {
                return;
            }

            var was_running = emulator.is_running();

            if(was_running)
            {
                await emulator.stop();
            }

            var filereader = new FileReader();
            filereader.onload = async function(e)
            {
                try
                {
                    await emulator.restore_state(e.target.result);
                }
                catch(err)
                {
                    alert("Something bad happened while restoring the state:\n" + err + "\n\n" +
                          "Note that the current configuration must be the same as the original");
                    throw err;
                }

                if(was_running)
                {
                    emulator.run();
                }
            };
            filereader.readAsArrayBuffer(file);

            this.value = "";
        };

        $("ctrlaltdel").onclick = function()
        {
            emulator.keyboard_send_scancodes([
                0x1D, // ctrl
                0x38, // alt
                0x53, // delete

                // break codes
                0x1D | 0x80,
                0x38 | 0x80,
                0x53 | 0x80,
            ]);

            $("ctrlaltdel").blur();
        };

        $("alttab").onclick = function()
        {
            emulator.keyboard_send_scancodes([
                0x38, // alt
                0x0F, // tab
            ]);

            setTimeout(function()
            {
                emulator.keyboard_send_scancodes([
                    0x38 | 0x80,
                    0x0F | 0x80,
                ]);
            }, 100);

            $("alttab").blur();
        };

        $("scale").onchange = function()
        {
            var n = parseFloat(this.value);

            if(n || n > 0)
            {
                emulator.screen_set_scale(n, n);
            }
        };

        $("fullscreen").onclick = function()
        {
            emulator.screen_go_fullscreen();
        };

        $("screen_container").onclick = function()
        {
            if(mouse_is_enabled && os_uses_mouse)
            {
                emulator.lock_mouse();
            }
            else
            {
                // allow text selection
                if(window.getSelection().isCollapsed)
                {
                    const phone_keyboard = document.getElementsByClassName("phone_keyboard")[0];

                    // stop mobile browser from scrolling into view when the keyboard is shown
                    phone_keyboard.style.top = document.body.scrollTop + 100 + "px";
                    phone_keyboard.style.left = document.body.scrollLeft + 100 + "px";

                    phone_keyboard.focus();
                }
            }
        };

        const phone_keyboard = document.getElementsByClassName("phone_keyboard")[0];

        phone_keyboard.setAttribute("autocorrect", "off");
        phone_keyboard.setAttribute("autocapitalize", "off");
        phone_keyboard.setAttribute("spellcheck", "false");
        phone_keyboard.tabIndex = 0;

        $("screen_container").addEventListener("mousedown", e =>
        {
            phone_keyboard.focus();
        }, false);

        $("take_screenshot").onclick = function()
        {
            const image = emulator.screen_make_screenshot();
            try {
                const w = window.open("");
                w.document.write(image.outerHTML);
            }
            catch(e) {}
            $("take_screenshot").blur();
        };

        if(emulator.speaker_adapter)
        {
            let is_muted = false;

            $("mute").onclick = function()
            {
                if(is_muted)
                {
                    emulator.speaker_adapter.mixer.set_volume(1, undefined);
                    is_muted = false;
                    $("mute").value = "Mute";
                }
                else
                {
                    emulator.speaker_adapter.mixer.set_volume(0, undefined);
                    is_muted = true;
                    $("mute").value = "Unmute";
                }

                $("mute").blur();
            };
        }
        else
        {
            $("mute").remove();
        }

        window.addEventListener("keydown", ctrl_w_rescue, false);
        window.addEventListener("keyup", ctrl_w_rescue, false);
        window.addEventListener("blur", ctrl_w_rescue, false);

        function ctrl_w_rescue(e)
        {
            if(e.ctrlKey)
            {
                window.onbeforeunload = function()
                {
                    window.onbeforeunload = null;
                    return "CTRL-W cannot be sent to the emulator.";
                };
            }
            else
            {
                window.onbeforeunload = null;
            }
        }

        const script = document.createElement("script");
        script.src = "build/xterm.js";
        script.async = true;
        script.onload = function()
        {
            emulator.set_serial_container_xtermjs($("terminal"));
        };
        document.body.appendChild(script);
    }

    function init_filesystem_panel(emulator)
    {
        $("filesystem_panel").style.display = "block";

        $("filesystem_send_file").onchange = function()
        {
            Array.prototype.forEach.call(this.files, function(file)
            {
                var loader = new v86util.SyncFileBuffer(file);
                loader.onload = function()
                {
                    loader.get_buffer(async function(buffer)
                    {
                        await emulator.create_file("/" + file.name, new Uint8Array(buffer));
                    });
                };
                loader.load();
            }, this);

            this.value = "";
            this.blur();
        };

        $("filesystem_get_file").onkeypress = async function(e)
        {
            if(e.which !== 13)
            {
                return;
            }

            this.disabled = true;

            let result;
            try
            {
                 result = await emulator.read_file(this.value);
            }
            catch(err)
            {
                console.log(err);
            }

            this.disabled = false;

            if(result)
            {
                var filename = this.value.replace(/\/$/, "").split("/");
                filename = filename[filename.length - 1] || "root";

                dump_file(result, filename);
                this.value = "";
            }
            else
            {
                alert("Can't read file");
            }
        };
    }

    function debug_start(emulator)
    {
        if(!emulator.v86)
        {
            return;
        }

        // called as soon as soon as emulation is started, in debug mode
        var debug = emulator.v86.cpu.debug;

        $("dump_gdt").onclick = debug.dump_gdt_ldt.bind(debug);
        $("dump_idt").onclick = debug.dump_idt.bind(debug);
        $("dump_regs").onclick = debug.dump_regs.bind(debug);
        $("dump_pt").onclick = debug.dump_page_structures.bind(debug);

        $("dump_log").onclick = function()
        {
            dump_file(log_data.join(""), "v86.log");
        };

        var cpu = emulator.v86.cpu;

        $("debug_panel").style.display = "block";
        setInterval(function()
        {
            $("debug_panel").textContent =
                cpu.debug.get_regs_short().join("\n") + "\n" + cpu.debug.get_state();

            $("dump_log").value = "Dump log" + (log_data.length ? " (" + log_data.length + " lines)" : "");
        }, 1000);

        // helps debugging
        window.emulator = emulator;
        window.cpu = cpu;
        window.dump_file = dump_file;
    }

    function onpopstate(e)
    {
        location.reload();
    }

    function set_profile(prof)
    {
        if(window.history.pushState)
        {
            window.history.pushState({ profile: prof }, "", "?profile=" + prof);
        }
    }

})();
