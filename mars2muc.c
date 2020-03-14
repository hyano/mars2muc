/*
 * mars2muc: decompiler from THE CURSE OF MARS (X1) to MUCOM88 MML
 *
 * Copyright (c) 2020 Hirokuni Yano
 *
 * Released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

/* use macro instead of expanding envelope command. */
#define USE_SSG_ENV_MACRO

/* typedef(s) */
typedef struct 
{
    const char *name;
    uint32_t data_addr;
    uint32_t table_offset;
    uint32_t table_size;
} driver_config_t;

/* global option(s) */
bool g_opt_verbose = false;
bool g_opt_ignore_warning = false;

#define BUFF_SIZE (16 * 1024)
uint8_t g_data[BUFF_SIZE];

#ifdef USE_SSG_ENV_MACRO
const char g_ssg_inst[] = 
"# *0{E$ff,$ff,$ff,$ff,$00,$ff}\n"
"# *1{E$ff,$ff,$ff,$c8,$00,$0a}\n"
"# *2{E$ff,$ff,$ff,$c8,$01,$0a}\n"
"# *3{E$ff,$ff,$ff,$be,$00,$0a}\n"
"# *4{E$ff,$ff,$ff,$be,$01,$0a}\n"
"# *5{E$ff,$ff,$ff,$aa,$00,$ff}\n"
"# *6{E$ff,$ff,$ff,$be,$0a,$0a}\n"
"# *7{E$ff,$ff,$ff,$00,$ff,$ff}\n"
"# *8{E$ff,$ff,$ff,$ff,$01,$0a}\n"
"# *9{E$64,$64,$ff,$ff,$01,$0a}\n"
"# *10{E$28,$02,$ff,$f0,$00,$0a}\n"
"# *11{E$ff,$ff,$ff,$c8,$01,$0a}\n"
"";
#endif /* USE_SSG_ENV_MACRO */
const uint8_t g_ssg_env[12][6] =
{
    {0xff, 0xff, 0xff, 0xff, 0x00, 0xff},
    {0xff, 0xff, 0xff, 0xc8, 0x00, 0x0a},
    {0xff, 0xff, 0xff, 0xc8, 0x01, 0x0a},
    {0xff, 0xff, 0xff, 0xbe, 0x00, 0x0a},
    {0xff, 0xff, 0xff, 0xbe, 0x01, 0x0a},
    {0xff, 0xff, 0xff, 0xaa, 0x00, 0xff},
    {0xff, 0xff, 0xff, 0xbe, 0x0a, 0x0a},
    {0xff, 0xff, 0xff, 0x00, 0xff, 0xff},
    {0xff, 0xff, 0xff, 0xff, 0x01, 0x0a},
    {0x64, 0x64, 0xff, 0xff, 0x01, 0x0a},
    {0x28, 0x02, 0xff, 0xf0, 0x00, 0x0a},
    {0xff, 0xff, 0xff, 0xc8, 0x01, 0x0a},
};

const driver_config_t g_driver_config[] =
{
    {"mars",    0xc000, 2,  13},
    {"algarna", 0xec00, 0,  13},
    {NULL,      0,      0,  0},
};

int DBG(const char *format, ...)
{
    va_list va;
    int ret = 0;

    va_start(va, format);
    if (g_opt_verbose)
    {
        ret = vprintf(format, va);
    }
    va_end(va);

    return ret;
}

int WARN(const char *format, ...)
{
    va_list va;
    int ret = 0;

    va_start(va, format);
    if (g_opt_verbose || !g_opt_ignore_warning)
    {
        ret = vprintf(format, va);
    }
    va_end(va);

    if (!g_opt_ignore_warning)
    {
        fprintf(stderr, "exit with warning. try -w option to apply workaround.\n");
        exit(1);
    }

    return ret;
}

uint32_t get_word(const uint8_t *p)
{
    return (uint32_t)p[0] + ((uint32_t)p[1] << 8);
}

void detect_clock(const uint32_t len_count[256], uint32_t *clock, uint32_t *deflen)
{
    const struct {
        uint32_t clock;
        uint32_t count;
    } count_table[] = {
        { 192, len_count[192] + len_count[96] + len_count[48] + len_count[24] + len_count[12] + len_count[6] + len_count[3]},
        { 144, len_count[144] + len_count[72] + len_count[36] + len_count[18] + len_count[ 9]},
        { 128, len_count[128] + len_count[64] + len_count[32] + len_count[16] + len_count[ 8] + len_count[4] + len_count[2]},
        { 112, len_count[112] + len_count[56] + len_count[28] + len_count[14] + len_count[7]},
        { 0, 0},
    };
    uint32_t c;
    uint32_t l;

    {
        DBG("----------------\n");
        for (uint32_t i = 0; count_table[i].clock != 0; i++)
        {
            DBG("%3d: %4d\n", count_table[i].clock, count_table[i].count);
        }
        DBG("--------\n");
        for (uint32_t i = 0; i < 20; i++)
        {
            DBG("%3d:", i*10);
            for (uint32_t j = 0; j < 10; j++)
            {
                DBG(" %4d", len_count[i * 10 + j]);
            }
            DBG("\n");
        }
        DBG("----------------\n");
    }

    c = 0;
    for (uint32_t i = 1; count_table[i].clock != 0; i++)
    {
        if (count_table[i].count > count_table[c].count)
        {
            c = i;
        }
    }

    l = 1;
    for (uint32_t i = 1; i < 7; i++)
    {
        if (len_count[count_table[c].clock / (1 << i)] > len_count[count_table[c].clock / l])
        {
            l = 1 << i;
        }
    }

    *clock = count_table[c].clock;
    *deflen = l;
}

void parse_music(
    const uint8_t *data, uint32_t offset,
    uint32_t *end, uint32_t *clock, uint32_t *deflen)
{
    const uint8_t *d = data;
    uint32_t o = offset;
    uint32_t c;
    uint32_t len;
    bool quit = false;
    uint32_t len_count[256];

    memset(len_count, 0, sizeof(len_count));

    while (!quit)
    {
        c = d[o++];
        if (c >= 0xf0)
        {
            switch (c)
            {
            case 0xf9:
            case 0xfb:
            case 0xfc:
            case 0xfd:
                break;
            case 0xf0:
            case 0xf1:
            case 0xf3:
            case 0xf7:
            case 0xf8:
            case 0xfe:
                o++;
                break;
            case 0xf2:
            case 0xf5:
                o += 2;
                break;
            case 0xfa:
                o += 6;
                break;
            case 0xf4:
                o += 7;
                break;
            case 0xf6:
                o++;
                o++;
                o += 2;
                break;
            case 0xff:
                c = d[o++] & 0x03;
                switch (c)
                {
                case 0x00:
                    o += 2;
                    break;
                case 0x01:
                    o += 1;
                    break;
                case 0x02:
                    o += 2;
                    break;
                case 0x03:
                    break;
                }
                break;
            }

        }
        else if (c == 0x00)
        {
            quit = true;
        }
        else if (c >= 0x80)
        {
            len = c & 0x7f;
            len_count[len]++;
        }
        else
        {
            len = c;
            len_count[len]++;
            o++;
        }
    }

    *end = o;

    detect_clock(len_count, clock, deflen);
}

int print_length(FILE *fp, uint32_t clock, uint32_t deflen, uint32_t len)
{
    int ret = 0;

    if (clock % len == 0)
    {
        if (clock / len == deflen)
        {
            /* nothing */
        }
        else
        {
            ret += fprintf(fp, "%u", clock / len);
        }
    }
    else if ((len % 3 == 0) && (clock % (len / 3 * 2) == 0))
    {
        if (clock / (len / 3 * 2) == deflen)
        {
            ret += fprintf(fp, ".");
        }
        else
        {
            ret += fprintf(fp, "%u.", clock / (len / 3 * 2));
        }
    }
    else
    {
        ret += fprintf(fp, "%%%u", len);
    }
    return ret;
}

void convert_music(FILE *fp, uint32_t music, uint32_t ch, const char *chname,
                   const uint8_t *data, const driver_config_t *config)
{
    static const char *notestr[16] = {
        "c", "c+", "d", "d+", "e", "f", "f+", "g", "g+", "a", "a+", "b",
        "?", "?", "?", "?"
    };
    const uint8_t *d = data;
    uint32_t mo = config->table_offset + music * config->table_size;
    uint32_t o = get_word(&data[mo + ch * 4]);
    uint32_t eo = get_word(&data[mo + ch * 4 + 2]);
    uint32_t end;
    uint32_t loop_offset = UINT32_MAX;
    uint32_t c;
    uint32_t prev_oct, oct, note, len;
    uint32_t clock, deflen;
    bool init = false;
    bool quit = false;
    int ll;

    o -= config->data_addr;
    if (eo != 0)
    {
        loop_offset = eo - config->data_addr;
    }
    parse_music(data, o, &end, &clock, &deflen);

    ll = 0;
    prev_oct = 0xff;

    while (!quit)
    {
        if (ll <= 0)
        {
            fprintf(fp, "\n");
            ll = 70;
            ll -= fprintf(fp, "%s ", chname);
            if (!init)
            {
                ll -= fprintf(fp, "C%ul%u", clock, deflen);
                init = true;
            }
        }

        if (o == loop_offset)
        {
            ll -= fprintf(fp, " L ");
        }

        c = d[o++];
        if (c >= 0xf0)
        {
            switch (c)
            {
            case 0xf0:
                c = d[o++];
#ifdef USE_SSG_ENV_MACRO
                ll -= fprintf(fp, "*%u", (uint32_t)(c & 0x0f));
#else /* USE_SSG_ENV_MACRO */
                ll -= fprintf(fp, "E%d,%d,%d,%d,%d,%d",
                              g_ssg_env[c][0], g_ssg_env[c][1], g_ssg_env[c][2],
                              g_ssg_env[c][3], g_ssg_env[c][4], g_ssg_env[c][5]);
#endif /* USE_SSG_ENV_MACRO */
                break;
            case 0xf1:
                ll -= fprintf(fp, "v%u", d[o++]);
                break;
            case 0xf2:
                ll -= fprintf(fp, "D%d", (int16_t)get_word(&d[o]));
                o += 2;
                break;
            case 0xf3:
                ll -= fprintf(fp, "q%d", d[o++]);
                break;
            case 0xf4:
                c = d[o++];
                if (c == 0x00)
                {
                    ll -= fprintf(fp, "M%u,%u,%d,%u",
                                  (uint32_t)d[o], (uint32_t)d[o + 1],
                                  -(int16_t)get_word(&d[o + 2]), (uint32_t)d[o + 4]);
                    o += 6;
                }
                else if (c == 0x01)
                {
                    ll -= fprintf(fp, "MF0");
                }
                else if (c == 0x02)
                {
                    ll -= fprintf(fp, "MF1");
                }
                else
                {
                    ll -= fprintf(fp, "??0x0f4,[%02x]", c);
                }
                break;
            case 0xf5:
                ll -= fprintf(fp, "[");
                o += 2;
                break;
            case 0xf6:
                DBG("{%04x:%04x}", o - 1, o + 4 - get_word(&d[o + 2]));
                ll -= fprintf(fp, "]%u", d[o+1]);
                o += 4;
                break;
            case 0xf7:
                c = d[o++];
                ll -= fprintf(fp, "P%u", ((c & 0x08) >> 3) | ((c & 0x01) << 1));
                break;
            case 0xf8:
                ll -= fprintf(fp, "w%u", d[o++]);
                break;
            case 0xf9:
                ll -= fprintf(fp, "&");
                break;
            case 0xfa:
                ll -= fprintf(fp, "E%u,%u,%u,%u,%u,%u",
                              (uint32_t)d[o + 0], (uint32_t)d[o + 1], (uint32_t)d[o + 2],
                              (uint32_t)d[o + 3], (uint32_t)d[o + 4], (uint32_t)d[o + 5]);
                o += 6;
                break;
            case 0xfb:
                ll -= fprintf(fp, ")");
                break;
            case 0xfc:
                ll -= fprintf(fp, "(");
                break;
            case 0xfd:
                ll -= fprintf(fp, "&");
                break;
            case 0xfe:
                ll -= fprintf(fp, " ?fe? ");
                o++;
                break;
            case 0xff:
                c = d[o++] & 0x03;
                switch (c)
                {
                case 0x00:
                    ll -= fprintf(fp, "/");
                    o += 2;
                    break;
                case 0x01:
                    ll -= fprintf(fp, "s%d", d[o]);
                    o += 1;
                    break;
                case 0x02:
                    ll -= fprintf(fp, "m%d", get_word(&d[o]));
                    o += 2;
                    break;
                case 0x03:
                    break;
                }
                break;
            }

        }
        else if (c == 0x00)
        {
            quit = true;
        }
        else if (c >= 0x80)
        {
            len = c & 0x7f;
            ll -= fprintf(fp, "r");
            ll -= print_length(fp, clock, deflen, len);
        }
        else
        {
            len = c;
            oct = ((d[o] >> 4) & 0x07) + 1;
            note = d[o] & 0x0f;
            if (note >= 12)
            {
                oct++;
                note -= 12;
            }
            if (oct != prev_oct)
            {
                if (oct == prev_oct + 1)
                {
                    ll -= fprintf(fp, ">");
                }
                else if (oct == prev_oct - 1)
                {
                    ll -= fprintf(fp, "<");
                }
                else
                {
                    ll -= fprintf(fp, "o%u", oct);
                }
                prev_oct = oct;
            }
            ll -= fprintf(fp, "%s", notestr[note]);
            ll -= print_length(fp, clock, deflen, len);
            o++;
        }
    }

    fprintf(fp, "\n");

}

void help(void)
{
    fprintf(stderr, "Usage: mars2muc [option(s)] file\n");
    fprintf(stderr, "  -h\t\tprint this help message and exit\n");
    fprintf(stderr, "  -v\t\tverbose (debug info)\n");
    fprintf(stderr, "  -w\t\tapply workaround and ignore warnings\n");
    fprintf(stderr, "  -o FILE\toutput file (default: stdout)\n");
    fprintf(stderr, "  -n BGM\tBGM number\n");
    fprintf(stderr, "  -m VERSION\tMUCOM88 version\n");
    fprintf(stderr, "  -t TITLE\ttitle for tag\n");
    fprintf(stderr, "  -a AUTHOR\tauthor for tag\n");
    fprintf(stderr, "  -c COMPOSER\tcomposer for tag\n");
    fprintf(stderr, "  -d DATE\tdate for tag\n");
    fprintf(stderr, "  -C COMMENT\tcomment for tag\n");
    fprintf(stderr, "  -F FORMAT\tfile format (default: mars)\n");
    fprintf(stderr, "\t\t  mars     = THE CURSE OF MARS\n");
    fprintf(stderr, "\t\t  algarna  = ALGARNA\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int c;
    FILE *fp;
    uint8_t *data = &g_data[0x0000];
    const driver_config_t *config = &g_driver_config[0];
    uint32_t music = 0;
    uint32_t ch;
    const char *chname[] = {"D", "E", "F"};
    const char *mucom88ver = NULL;
    const char *title = NULL;
    const char *author = NULL;
    const char *composer = NULL;
    const char *date = NULL;
    const char *comment = NULL;
    const char *outfile = NULL;

    /* command line options */
    while ((c = getopt(argc, argv, "vwo:n:m:t:a:c:d:C:F:")) != -1)
    {
        switch (c)
        {
        case 'v':
            /* debug option */
            g_opt_verbose = true;
            break;
        case 'w':
            /* apply workaround and ignore warnings */
            g_opt_ignore_warning = true;
            break;
        case 'o':
            outfile = optarg;
            break;
        case 'n':
            music = atoi(optarg);
            break;
        case 'm':
            /* 1.7 is required for using "r%n" */
            mucom88ver = optarg;
            break;
        case 't':
            title = optarg;
            break;
        case 'a':
            author = optarg;
            break;
        case 'c':
            composer = optarg;
            break;
        case 'd':
            date = optarg;
            break;
        case 'C':
            comment = optarg;
            break;
        case 'F':
            config = NULL;
            for (int i = 0; g_driver_config[i].name != NULL; i++)
            {
                if (strcmp(optarg, g_driver_config[i].name) == 0)
                {
                    config = &g_driver_config[i];
                    break;
                }
            }
            break;
        default:
            help();
            break;
        }
    }

    if (optind != argc - 1)
    {
        help();
    }

    if (config == NULL)
    {
        fprintf(stderr, "Unknown driver type\n");
        exit(1);
    }

    /* read data to buffer */
    fp = fopen(argv[optind], "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "Can't open '%s'\n", argv[optind]);
        exit(1);
    }
    fread(g_data, sizeof(uint8_t), sizeof(g_data), fp);
    fclose(fp);

    if (outfile != NULL)
    {
        fp = fopen(outfile, "w");
        if (fp == NULL)
        {
            fprintf(stderr, "Can't open '%s'\n", outfile);
            exit(1);
        }
    }
    else
    {
        fp = stdout;
    }

    /* insert tag */
    if (mucom88ver != NULL)
    {
        fprintf(fp, "#mucom88 %s\n", mucom88ver);
    }
    if (title != NULL)
    {
        fprintf(fp, "#title %s\n", title);
    }
    if (author != NULL)
    {
        fprintf(fp, "#author %s\n", author);
    }
    if (composer != NULL)
    {
        fprintf(fp, "#composer %s\n", composer);
    }
    if (date != NULL)
    {
        fprintf(fp, "#date %s\n", date);
    }
    if (comment != NULL)
    {
        fprintf(fp, "#comment %s\n", comment);
    }
    fprintf(fp, "\n");

    /* convert */
#ifdef USE_SSG_ENV_MACRO
    fprintf(fp, "%s", g_ssg_inst);
#endif /* USE_SSG_ENV_MACRO */

    fprintf(fp, "A t199\n");

    for (ch = 0; ch < 3; ch++)
    {
        convert_music(
            fp,
            music, 
            ch, chname[ch],
            data, config);
    }
    fclose(fp);

    if (outfile)
    {
        fclose(fp);
    }

    return 0;
}
