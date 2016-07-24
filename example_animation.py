plt.rcParams['animation.ffmpeg_path'] = '/usr/local/Cellar/ffmpeg/3.1.1/bin/ffmpeg'
xx = list(data_repeat_webscrp.num_days)
zz = list(data_repeat_webscrp.num_ips)
yy = list(data_repeat_webscrp.days_gap)
fig = plt.figure()
ax = Axes3D(fig)
fig.suptitle('WEBSCRP gap days')
def init():
    x = np.linspace(0, 100, 100)
    y = np.linspace(0, 100, 100)
    ax.scatter(xx, yy, zz, marker='o', s=20, c="goldenrod", alpha=0.6)
    ax.set_xlabel('Number of active days')
    ax.set_ylabel('Number of gap days')
    ax.set_zlabel('number of IPs')

def animate(i):
    ax.view_init(elev=10., azim=i)

# Animate
anim = animation.FuncAnimation(fig, animate, init_func=init,
                               frames=360, interval=20)
# Save
mywriter = animation.FFMpegWriter()
anim.save('gap_days_graphs/basic_animation_webscrp.mp4', mywriter)