#include <stdint.h>
#include <sys/types.h>
#include <math.h>
#include <fcntl.h>
#include <utils/misc.h>
#include <signal.h>

#include <binder/IPCThreadState.h>
#include <utils/threads.h>
#include <utils/Atomic.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/AssetManager.h>

#include <ui/PixelFormat.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/DisplayInfo.h>

#include <surfaceflinger/ISurfaceComposer.h>
#include <surfaceflinger/ISurfaceComposerClient.h>
#include <surfaceflinger/SurfaceComposerClient.h>

#include <core/SkBitmap.h>
#include <core/SkCanvas.h>
#include <core/SkRegion.h>
#include <core/SkStream.h>
#include <images/SkImageDecoder.h>

#include "auth_log.h"
#include "auth_screen.h"

using namespace android;

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) sizeof(a)/sizeof(a[0]) 
#endif

static char builtin_bmp[]=
{
#include "auth_screenlock.in"    
};

static inline SkBitmap::Config convertPixelFormat(PixelFormat format)
{
    /* note: if PIXEL_FORMAT_RGBX_8888 means that all alpha bytes are 0xFF, then
        we can map to SkBitmap::kARGB_8888_Config, and optionally call
        bitmap.setIsOpaque(true) on the resulting SkBitmap (as an accelerator)
    */
    switch (format) {
    case PIXEL_FORMAT_RGBX_8888:    return SkBitmap::kARGB_8888_Config;
    case PIXEL_FORMAT_RGBA_8888:    return SkBitmap::kARGB_8888_Config;
    case PIXEL_FORMAT_RGBA_4444:    return SkBitmap::kARGB_4444_Config;
    case PIXEL_FORMAT_RGB_565:      return SkBitmap::kRGB_565_Config;
    case PIXEL_FORMAT_A_8:          return SkBitmap::kA8_Config;
    default:                        return SkBitmap::kNo_Config;
    }
}

class AuthScreen: public IBinder::DeathRecipient
{
    public:
        AuthScreen(){            
            mSession = new SurfaceComposerClient();   
        }
        virtual ~AuthScreen(){
            
        }
    public:
            bool lock(const char* File){
                SkBitmap bitmap;            

                
                //
                //draw bitmap on surface        
                //
                if(File)
                {
                    SkImageDecoder::DecodeFile(File,&bitmap);
                }
                else
                {
                    //use built in bmp
                    SkImageDecoder::DecodeMemory(builtin_bmp,ARRAYSIZE(builtin_bmp),&bitmap);
                }
                
                mSession->openTransaction();
                mFlingerSurfaceControl->show();
                mSession->closeTransaction();
                if(true==lock_canvas())
                {
                    //display in center
                    int w = bitmap.width();
                    int h = bitmap.height();
                    //calculate center location
                    int left,top;
                    left = (dinfo.w-w)/2;
                    top = (dinfo.h-h)/2;
                    
                    canvas.drawSprite(bitmap,left,top,NULL);
                    unlock_canvas_and_post();
                    
                    //do composer lock
                    mSession->freezeDisplay(0,0);
                    
                } else{
                    ERROR("lock canvas failed\n ");
                    return false;                
                }
                return true;
            }
            bool unlock(){                
                mSession->openTransaction();
                mFlingerSurfaceControl->hide();
                mSession->closeTransaction();
                
                //do unfreeze
                if(mSession!=0)
                    mSession->unfreezeDisplay(0,0);
                return true;
            }
        
    protected:        
        bool lock_canvas(void){
            SkBitmap bitmap;            
            
            if (!Surface::isValid(mFlingerSurface))
            {
                WARN("surface invalid surface=%d\n",(mFlingerSurface==0)?0:1);
                return false;
            }
            
            Surface::SurfaceInfo info;
            // set dirty region
            Region dirtyRegion;
            dirtyRegion.set(Rect(0x3FFF,0x3FFF));
            
            status_t err = mFlingerSurface->lock(&info, &dirtyRegion);
            if (err < 0) {
                ERROR("lock flinger surface failed(%s)\n",strerror(-err));
                return false;
            }
            
            // Associate a SkCanvas object to this surface
            if (info.w > 0 && info.h > 0) {
                bitmap.setPixels(info.bits);
            } else {
                // be safe with an empty bitmap.
                bitmap.setPixels(NULL);
            }
       
            ssize_t bpr = info.s * bytesPerPixel(info.format);
            bitmap.setConfig(convertPixelFormat(info.format), info.w, info.h, bpr);
            if (info.format == PIXEL_FORMAT_RGBX_8888) {
                bitmap.setIsOpaque(true);
            }
            if (info.w > 0 && info.h > 0) {
                bitmap.setPixels(info.bits);
            } else {
                // be safe with an empty bitmap.
                bitmap.setPixels(NULL);
            }
            
            canvas.setBitmapDevice(bitmap);

            

            SkRegion clipReg;
            if (dirtyRegion.isRect()) { // very common case
                const Rect b(dirtyRegion.getBounds());
                clipReg.setRect(b.left, b.top, b.right, b.bottom);
            } else {
                size_t count;
                Rect const* r = dirtyRegion.getArray(&count);
                while (count) {
                    clipReg.op(r->left, r->top, r->right, r->bottom, SkRegion::kUnion_Op);
                    r++, count--;
                }
            }
            
            canvas.clipRegion(clipReg);

            saveCount = canvas.save();            


            
            return true;
        }
        bool unlock_canvas_and_post(){
            if (!Surface::isValid(mFlingerSurface))
                return false;

            // detach the canvas from the surface
            canvas.restoreToCount(saveCount);
            canvas.setBitmapDevice(SkBitmap());
            saveCount = 0;

            // unlock surface
            status_t err = mFlingerSurface->unlockAndPost();
            if (err < 0) {
                ERROR("unlockAndPost surface failed(%s)\n",strerror(-err));
                return false;
            }

            return true;
    
        }
    private:        
        virtual void  binderDied(const wp<IBinder>& who){            
            // woah, surfaceflinger died!
            ERROR("SurfaceFlinger died, exiting...");            
            kill( getpid(), SIGKILL );
        }
        virtual void        onFirstRef(){
            status_t err = mSession->linkToComposerDeath(this);
            if(err) ERROR("linkToComposerDeath failed (%s) ", strerror(-err));
            err = mSession->initCheck();
            if(err) ERROR("init check failed (%s) ", strerror(-err));

            //init surface
            err = mSession->getDisplayInfo(0, &dinfo);
            if(err) ERROR("getDisplayInfo failed (%s) ", strerror(-err));
            INFO("display [%dx%d]\n",dinfo.w,dinfo.h);
            // create the native surface
            mFlingerSurfaceControl = mSession->createSurface(
                    getpid(), 0, dinfo.w, dinfo.h, PIXEL_FORMAT_RGB_565);
            if(mFlingerSurfaceControl==0)
            {
                ERROR("failed to create surface\n");
            }
            else
            {
                mSession->openTransaction();
                mFlingerSurfaceControl->hide();
                mFlingerSurfaceControl->setLayer(0x50000000);
                mSession->closeTransaction();
            }            
            mFlingerSurface = mFlingerSurfaceControl->getSurface();
            if(mFlingerSurface==0)
            {
                ERROR("failed to get surface obj\n");
            }

            
        }
        
    private:
        sp<SurfaceComposerClient>       mSession;
        sp<SurfaceControl> mFlingerSurfaceControl;
        sp<Surface> mFlingerSurface;
        DisplayInfo dinfo;

        int saveCount;
        SkCanvas canvas;
        
};

static sp<AuthScreen> screenlock;

int auth_screen_init(void)
{
    if(screenlock==0)
        screenlock = new AuthScreen();
    return 0;
}

//only png name supported
int auth_screen_lock(const char* name)
{
    if(screenlock==0)
        screenlock = new AuthScreen();
    if(screenlock!=0)
        screenlock->lock(name);
    else{
        WARN("screen lock obj not ready\n");
    }
	return 0;
}
int auth_screen_unlock(void)
{
    if(screenlock==0)
        screenlock = new AuthScreen();
    if(screenlock!=0)
        screenlock->unlock();
    else {
        WARN("screen lock obj not ready\n");        
    }
	return 0;
}



