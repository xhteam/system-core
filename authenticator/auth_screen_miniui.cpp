#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#include <utils/misc.h>
#include <signal.h>
#include "auth_log.h"
#include "auth_screen.h"
#include <cutils/properties.h>
#include "minui.h"


#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) sizeof(a)/sizeof(a[0]) 
#endif
#define MSEC_PER_SEC            (1000LL)
#define NSEC_PER_MSEC           (1000000LL)

#define DEFAULT_SCRAMBER_TIME    (2 * MSEC_PER_SEC)

struct frame {
    const char *name;
    int disp_time;
    int min_capacity;
    bool level_only;

    gr_surface surface;
};

struct animation {
    bool run;

    struct frame *frames;
    int cur_frame;
    int num_frames;

    int cur_cycle;
    int num_cycles;

};


struct screen_scramber {
    int64_t next_screen_transition;
    struct animation *scramber_anim;
};

static struct frame scramber_anim_frames[] = {
    { "authenticator/auth_f1",750,0,0,NULL  },
    { "authenticator/auth_f2",750,20,0,NULL },
};

static struct animation scramber_animation = {
	true,
	scramber_anim_frames,
	0,
	ARRAY_SIZE(scramber_anim_frames),
	0,
    3,
};

static struct screen_scramber scramber_state = {
	0,
    &scramber_animation,
};



static int char_width;
static int char_height;
static int inited=0;

/* current time in milliseconds */
static int64_t curr_time_ms(void)
{
    struct timespec tm;
    clock_gettime(CLOCK_MONOTONIC, &tm);
    return tm.tv_sec * MSEC_PER_SEC + (tm.tv_nsec / NSEC_PER_MSEC);
}

static void clear_screen(void)
{
    gr_color(0, 0, 0, 255);
    gr_fill(0, 0, gr_fb_width(), gr_fb_height());
};


static int draw_text(const char *str, int x, int y)
{
    int str_len_px = gr_measure(str);

    if (x < 0)
        x = (gr_fb_width() - str_len_px) / 2;
    if (y < 0)
        y = (gr_fb_height() - char_height) / 2;
    gr_text(x, y, str);

    return y + char_height;
}

static void android_green(void)
{
    gr_color(0xa4, 0xc6, 0x39, 255);
}

/* returns the last y-offset of where the surface ends */
static int draw_surface_centered(struct screen_scramber *scramber, gr_surface surface)
{
    int w;
    int h;
    int x;
    int y;

    w = gr_get_width(surface);
    h = gr_get_height(surface);
    x = (gr_fb_width() - w) / 2 ;
    y = (gr_fb_height() - h) / 2 ;

    DBG("drawing surface %dx%d+%d+%d\n", w, h, x, y);
    gr_blit(surface, 0, 0, w, h, x, y);
    return y + h;
}

static void draw_scramber(struct screen_scramber *scramber)
{
    struct animation *scramber_anim = scramber->scramber_anim;
    struct frame *frame = &scramber_anim->frames[scramber_anim->cur_frame];

    if (scramber_anim->num_frames != 0) {
        draw_surface_centered(scramber, frame->surface);
        DBG("drawing frame #%d name=%s min_cap=%d time=%d\n",
             scramber_anim->cur_frame, frame->name, frame->min_capacity,
             frame->disp_time);
    }
}

static void redraw_screen(struct screen_scramber *scramber)
{

    clear_screen();
    draw_scramber(scramber);
    gr_flip();
}

static void kick_animation(struct animation *anim)
{
    anim->run = true;
}

static void reset_animation(struct animation *anim)
{
    anim->cur_cycle = 0;
    anim->cur_frame = 0;
    anim->run = false;
}


static void update_screen_state(struct screen_scramber *scramber, int64_t now)
{
    struct animation *scramber_anim = scramber->scramber_anim;
    int cur_frame;
    int disp_time;

    if (!scramber_anim->run || now < scramber->next_screen_transition)
        return;

	DBG("run animation prepare\n");
    /* animation is over, blank screen and leave */
    if (scramber_anim->cur_cycle == scramber_anim->num_cycles) {
        reset_animation(scramber_anim);
        scramber->next_screen_transition = -1;
        gr_fb_blank(true);
        DBG("[%lld] animation done\n", now);
        return;
    }

    disp_time = scramber_anim->frames[scramber_anim->cur_frame].disp_time;

    /* animation starting, set up the animation */
    if (scramber_anim->cur_frame == 0) {
            scramber_anim->cur_frame++;
			if(scramber_anim->cur_frame>scramber_anim->num_frames)
				scramber_anim->cur_frame=0;
            /* show the first frame for twice as long */
            disp_time = scramber_anim->frames[scramber_anim->cur_frame].disp_time * 2;
    }

    /* unblank the screen  on first cycle */
    if (scramber_anim->cur_cycle == 0)
        gr_fb_blank(false);

    /* draw the new frame (@ cur_frame) */
    redraw_screen(scramber);

    /* if we don't have anim frames, we only have one image, so just bump
     * the cycle counter and exit
     */
    if (scramber_anim->num_frames == 0 ) {
        DBG("[%lld] animation missing or unknown battery status\n", now);
        scramber->next_screen_transition = now + DEFAULT_SCRAMBER_TIME;
        scramber_anim->cur_cycle++;
        return;
    }

    /* schedule next screen transition */
    scramber->next_screen_transition = now + disp_time;

    /* advance frame cntr to the next valid frame
     * if necessary, advance cycle cntr, and reset frame cntr
     */
    scramber_anim->cur_frame++;

    /* if the frame is used for level-only, that is only show it when it's
     * the current level, skip it during the animation.
     */
    while (scramber_anim->cur_frame < scramber_anim->num_frames &&
           scramber_anim->frames[scramber_anim->cur_frame].level_only)
        scramber_anim->cur_frame++;
    if (scramber_anim->cur_frame >= scramber_anim->num_frames) {
        scramber_anim->cur_cycle++;
        scramber_anim->cur_frame = 0;

        /* don't reset the cycle counter, since we use that as a signal
         * in a test above to check if animation is over
         */
    }
}

static int draw_scramber_surface(void){
	int ret = gr_init();
	if(ret) {			
		ERROR("Cannot init graphics[%d]\n", ret);
		return ret;
	}
	struct screen_scramber *scramber = &scramber_state;
	struct frame* frame = &scramber_anim_frames[scramber_animation.cur_frame++];
	gr_surface surface;
	if(scramber_animation.cur_frame>=ARRAY_SIZE(scramber_anim_frames)){
		scramber_animation.cur_frame=0;
	}
	ret = res_create_surface(frame->name, &surface);
    clear_screen();
	draw_surface_centered(scramber,surface);
    gr_flip();

	//turn on backlight	
	char value[PROPERTY_VALUE_MAX];
	char path[256],max_path[256];
	int brightness,max_brightness;
	FILE* file;
	property_get("hw.backlight.dev", value, "pwm-backlight");
    strcpy(path, "/sys/class/backlight/");
	strcat(path, value);	
	strcpy(max_path, path);
	strcat(max_path, "/max_brightness");
	strcat(path, "/brightness");

	
    file = fopen(max_path, "r");
    if (!file) {
        ERROR("can not open file %s\n", max_path);
        return -1;;
    }
    fread(&max_brightness, 1, 3, file);
    fclose(file);

	atoi((char *) &max_brightness);

	brightness = max_brightness/2;
	
    file = fopen(path, "w");
    if (!file) {
        ERROR("can not open file %s\n", path);
        return -2;
    }
    fprintf(file, "%d", brightness);
    fclose(file);
	
	res_free_surface(surface);
	gr_exit();

	return 0;
}
int auth_screen_init(void)
{
    if(!inited){    	
		inited++;
    }
    return 0;
}

//only png name supported
int auth_screen_lock(const char* name)
{	
	pid_t child,pid;
	int status;
	if(!inited) auth_screen_init();	
    child = fork();
    if (child < 0) {
        ERROR("error: auth screen scramber: fork failed\n");
        return 0;
    }
    if (child == 0) {
        execl("/system/bin/stop", "/system/bin/stop",NULL);
        exit(-1);
    }

    while ((pid=waitpid(-1, &status, 0)) != child) {
        if (pid == -1) {
            ERROR("auth screen scramber failed!\n");
            return 1;
        }
    }
	draw_scramber_surface();
	return 0;
}
int auth_screen_unlock(void)
{
	if(!inited) auth_screen_init();

	//do nothing,
	return 0;
}


